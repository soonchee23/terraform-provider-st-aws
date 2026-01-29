package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsIamClient "github.com/aws/aws-sdk-go-v2/service/iam"
	awsSsoAdminClient "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

const (
	// Number of 30 indicates the character length of neccessary policy keyword
	// such as "Version" and "Statement" and some JSON symbols ({}, []).
	policyKeywordLength = 30
	policyMaxLength     = 6144
)

type awsIamClientInterface interface {
	ListPolicies(ctx context.Context, input *awsIamClient.ListPoliciesInput, opts ...func(*awsIamClient.Options)) (*awsIamClient.ListPoliciesOutput, error)
}

type policyDetailInterface interface {
	GetName() string
}

type PoliciesState interface {
	GetAttachedPoliciesDetail() []*policyV2Detail
	SetAttachedPoliciesToNull()
}

type PolicyDetail interface {
	GetPolicyName() string
	GetPolicyDocument() string
}

func (p *policyV2Detail) GetName() string {
	return p.PolicyName.ValueString()
}

func handleAPIError(err error) error {
	var ae smithy.APIError

	if errors.As(err, &ae) {
		if isAbleToRetry(ae.ErrorCode()) {
			return err
		} else {
			return backoff.Permanent(err)
		}
	} else {
		return backoff.Permanent(err)
	}
}

func addDiagnostics(diags *diag.Diagnostics, severity string, title string, errors []error, extraMessage string) {
	var combinedMessages string
	validErrors := 0

	for _, err := range errors {
		if err != nil {
			combinedMessages += fmt.Sprintf("%v\n", err)
			validErrors++
		}
	}

	if validErrors == 0 {
		return
	}

	var message string
	if extraMessage != "" {
		message = fmt.Sprintf("%s\n%s", extraMessage, combinedMessages)
	} else {
		message = combinedMessages
	}

	switch severity {
	case "warning":
		diags.AddWarning(title, message)
	case "error":
		diags.AddError(title, message)
	default:
		// Handle unknown severity if needed
	}
}

func checkPoliciesDriftHelper(newState, oriState PoliciesState) error {
	var driftedPolicies []string

	for _, oldPolicyDetailState := range oriState.GetAttachedPoliciesDetail() {
		for _, currPolicyDetailState := range newState.GetAttachedPoliciesDetail() {
			if oldPolicyDetailState.PolicyName.String() == currPolicyDetailState.PolicyName.String() {
				if oldPolicyDetailState.PolicyDocument.String() != currPolicyDetailState.PolicyDocument.String() {
					driftedPolicies = append(driftedPolicies, oldPolicyDetailState.PolicyName.String())
				}
				break
			}
		}
	}

	if len(driftedPolicies) > 0 {
		newState.SetAttachedPoliciesToNull()
		return fmt.Errorf(
			"the following policies documents had been changed since combining policies: [%s]",
			strings.Join(driftedPolicies, ", "),
		)
	}

	return nil
}

func combinePolicyDocumentsHelper(attachedPolicies []PolicyDetail, keywordLength int, maxLength int) (combinedPolicyDocument []string, excludedPolicies []PolicyDetail, errList []error) {
	currentLength := 0
	currentPolicyDocument := ""
	appendedPolicyDocument := make([]string, 0)

	for _, attachedPolicy := range attachedPolicies {
		tempPolicyDocument, err := url.QueryUnescape(attachedPolicy.GetPolicyDocument())
		if err != nil {
			errList = append(errList, err)
			return nil, nil, errList
		}

		// If the policy itself have more than 6144 characters, then skip the combine
		// policy part since splitting the policy "statement" will be hitting the
		// limitation of "maximum number of attached policies" easily.
		noWhitespace := strings.Join(strings.Fields(tempPolicyDocument), "") //removes any whitespace including \t and \n
		if len(noWhitespace) > policyMaxLength {                             // policyMaxLength can be a global const
			excludedPolicies = append(excludedPolicies, attachedPolicy)
			continue
		}

		var data map[string]interface{}
		if err := json.Unmarshal([]byte(tempPolicyDocument), &data); err != nil {
			errList = append(errList, err)
			return nil, nil, errList
		}

		statementBytes, err := json.Marshal(data["Statement"])
		if err != nil {
			errList = append(errList, err)
			return nil, nil, errList
		}

		finalStatement := strings.Trim(string(statementBytes), "[]")
		currentLength += len(finalStatement)

		// Before further proceeding the current policy, we need to add a number
		// of 'policyKeywordLength' to simulate the total length of completed
		// policy to check whether it is already execeeded the max character
		// length of 6144.
		if (currentLength + keywordLength) > maxLength {
			currentPolicyDocument = strings.TrimSuffix(currentPolicyDocument, ",")
			appendedPolicyDocument = append(appendedPolicyDocument, currentPolicyDocument)
			currentPolicyDocument = finalStatement + ","
			currentLength = len(finalStatement)
		} else {
			currentPolicyDocument += finalStatement + ","
		}
	}

	if len(currentPolicyDocument) > 0 {
		currentPolicyDocument = strings.TrimSuffix(currentPolicyDocument, ",")
		appendedPolicyDocument = append(appendedPolicyDocument, currentPolicyDocument)
	}

	for _, policyStatement := range appendedPolicyDocument {
		combinedPolicyDocument = append(combinedPolicyDocument, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[%v]}`, policyStatement))
	}

	return combinedPolicyDocument, excludedPolicies, nil
}

func fetchPoliciesHelper[T any](ctx context.Context, policiesName []string, getPolicyArn func(ctx context.Context, policy string) (string, string, error), createPolicyDetail func(name, document string) T, client *awsIamClient.Client) (policiesDetail []T, notExistError, unexpectedError []error) {
	var getPolicyDocumentResponse *awsIamClient.GetPolicyVersionOutput
	var getPolicyNameResponse *awsIamClient.GetPolicyOutput
	var ae smithy.APIError

	for _, attachedPolicy := range policiesName {
		policyArn, policyVersionId, err := getPolicyArn(ctx, attachedPolicy)

		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				notExistError = append(notExistError, err)
				continue
			}

			unexpectedError = append(unexpectedError, err)
			continue
		}

		if policyArn == "" && policyVersionId == "" {
			notExistError = append(notExistError, fmt.Errorf("policy %v does not exist", attachedPolicy))
			continue
		}

		getPolicy := func() error {
			getPolicyDocumentRequest := &awsIamClient.GetPolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String(policyVersionId),
			}

			getPolicyDocumentResponse, err = client.GetPolicyVersion(ctx, getPolicyDocumentRequest)
			if err != nil {
				return handleAPIError(err)
			}

			getPolicyNameRequest := &awsIamClient.GetPolicyInput{
				PolicyArn: aws.String(policyArn),
			}

			getPolicyNameResponse, err = client.GetPolicy(ctx, getPolicyNameRequest)
			if err != nil {
				return handleAPIError(err)
			}
			return nil
		}

		reconnectBackoff := backoff.NewExponentialBackOff()
		reconnectBackoff.MaxElapsedTime = 30 * time.Second
		err = backoff.Retry(getPolicy, reconnectBackoff)

		// Handle permanent error returned from API.
		if err != nil && errors.As(err, &ae) {
			switch ae.ErrorCode() {
			case "NoSuchEntity":
				notExistError = append(notExistError, err)
			default:
				unexpectedError = append(unexpectedError, err)
			}
		} else {
			policiesDetail = append(policiesDetail, createPolicyDetail(
				*getPolicyNameResponse.Policy.PolicyName,
				*getPolicyDocumentResponse.PolicyVersion.Document,
			))
		}
	}

	return
}

func getPolicyArnHelper(ctx context.Context, client awsIamClientInterface, policyName string) (policyArn string, policyVersionId string, err error) {
	var listPoliciesResponse *awsIamClient.ListPoliciesOutput

	listPolicies := func() error {
		listPoliciesResponse, err = client.ListPolicies(ctx, &awsIamClient.ListPoliciesInput{
			MaxItems: aws.Int32(1000),
			Scope:    "All",
		})
		if err != nil {
			return handleAPIError(err)
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err = backoff.Retry(listPolicies, reconnectBackoff)
	if err != nil {
		return "", "", err
	}

	for _, policyObj := range listPoliciesResponse.Policies {
		if *policyObj.PolicyName == policyName {
			return *policyObj.Arn, *policyObj.DefaultVersionId, nil
		}
	}

	return "", "", fmt.Errorf("policy %s not found", policyName)
}

func attachCustomerPoliciesHelper(ctx context.Context, ssoClient *awsSsoAdminClient.Client, instanceArn, permissionSetArn, path string, policies []policyDetailInterface) (unexpectedError []error) {
	if path == "" {
		path = "/"
	}

	attachCustomerPoliciesToPermissionSet := func() error {
		for _, policy := range policies {
			attachCustomerManagedPoliciesReferenceToPermissionSetInputRequest := &awsSsoAdminClient.AttachCustomerManagedPolicyReferenceToPermissionSetInput{
				InstanceArn:      aws.String(instanceArn),
				PermissionSetArn: aws.String(permissionSetArn),
				CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
					Name: aws.String(policy.GetName()),
					Path: aws.String(path),
				},
			}
			if _, err := ssoClient.AttachCustomerManagedPolicyReferenceToPermissionSet(ctx, attachCustomerManagedPoliciesReferenceToPermissionSetInputRequest); err != nil {
				return handleAPIError(err)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachCustomerPoliciesToPermissionSet, reconnectBackoff); err != nil {
		unexpectedError = append(unexpectedError, err)
	}
	return unexpectedError
}

func attachAWSManagedPoliciesHelper(ctx context.Context, ssoClient *awsSsoAdminClient.Client, instanceArn, permissionSetArn string, awsManagedPolicyArns []string) (unexpectedError []error) {
	attachAWSManagedPoliciesToPermissionSet := func() error {
		for _, awsManagedPolicyArn := range awsManagedPolicyArns {
			req := &awsSsoAdminClient.AttachManagedPolicyToPermissionSetInput{
				InstanceArn:      aws.String(instanceArn),
				PermissionSetArn: aws.String(permissionSetArn),
				ManagedPolicyArn: aws.String(awsManagedPolicyArn),
			}
			if _, err := ssoClient.AttachManagedPolicyToPermissionSet(ctx, req); err != nil {
				return handleAPIError(err)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachAWSManagedPoliciesToPermissionSet, reconnectBackoff); err != nil {
		unexpectedError = append(unexpectedError, err)
	}
	return unexpectedError
}

func provisionPermissionSetAllWaitHelper(ctx context.Context, ssoClient *awsSsoAdminClient.Client, instanceArn, permissionSetArn string, maxWait time.Duration) (ok bool, unexpectedErrs []error) {
	var reqID string
	provisionPermissionSetRequest := func() error {
		provisionPermissionSet, err := ssoClient.ProvisionPermissionSet(ctx, &awsSsoAdminClient.ProvisionPermissionSetInput{
			InstanceArn:      aws.String(instanceArn),
			PermissionSetArn: aws.String(permissionSetArn),
			TargetType:       ssoTypes.ProvisionTargetTypeAllProvisionedAccounts,
		})
		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) && (ae.ErrorCode() == "ThrottlingException" || ae.ErrorCode() == "TooManyRequestsException" || ae.ErrorCode() == "ProvisioningInProgressException") {
				return err
			}
			return backoff.Permanent(handleAPIError(err))
		}
		if provisionPermissionSet == nil || provisionPermissionSet.PermissionSetProvisioningStatus == nil || provisionPermissionSet.PermissionSetProvisioningStatus.RequestId == nil {
			return fmt.Errorf("provision call returned no request id")
		}
		reqID = aws.ToString(provisionPermissionSet.PermissionSetProvisioningStatus.RequestId)
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 2 * time.Minute
	if err := backoff.Retry(provisionPermissionSetRequest, reconnectBackoff); err != nil {
		return false, []error{err}
	}

	waitBackoff := backoff.NewExponentialBackOff()
	waitBackoff.MaxElapsedTime = maxWait

	describePermissionSetProvisioningStatusRequest := backoff.Retry(func() error {
		describePermissionSetProvisioningStatus, err := ssoClient.DescribePermissionSetProvisioningStatus(ctx, &awsSsoAdminClient.DescribePermissionSetProvisioningStatusInput{
			InstanceArn:                     aws.String(instanceArn),
			ProvisionPermissionSetRequestId: aws.String(reqID),
		})
		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) && (ae.ErrorCode() == "ThrottlingException" || ae.ErrorCode() == "TooManyRequestsException") {
				return err
			}
			return backoff.Permanent(err)
		}
		if describePermissionSetProvisioningStatus == nil || describePermissionSetProvisioningStatus.PermissionSetProvisioningStatus == nil {
			return fmt.Errorf("empty provisioning status for %s", reqID)
		}
		switch describePermissionSetProvisioningStatus.PermissionSetProvisioningStatus.Status {
		case ssoTypes.StatusValuesSucceeded:
			return nil
		case ssoTypes.StatusValuesFailed:
			return backoff.Permanent(fmt.Errorf("provisioning %s failed: %s",
				reqID, aws.ToString(describePermissionSetProvisioningStatus.PermissionSetProvisioningStatus.FailureReason)))
		default:
			return fmt.Errorf("still waiting on provisioning %s", reqID)
		}
	}, waitBackoff)

	if describePermissionSetProvisioningStatusRequest != nil {
		return false, []error{describePermissionSetProvisioningStatusRequest}
	}
	return true, nil
}

func attachPoliciesToPermissionSetHelper(ctx context.Context, ssoClient *awsSsoAdminClient.Client, iamClient awsIamClientInterface, combinedPolicies []policyDetailInterface, instanceArn, permissionSetArn, permissionSetName, path string, provisionTimeout time.Duration) (unexpectedErrs []error) {
	if len(combinedPolicies) == 0 {
		if ok, errs := provisionPermissionSetAllWaitHelper(ctx, ssoClient, instanceArn, permissionSetArn, provisionTimeout); !ok {
			return append(unexpectedErrs, errs...)
		}
		return nil
	}

	prefix := permissionSetName + "-"
	var customerManagedPolicies []policyDetailInterface
	var awsManagedPolicies []policyDetailInterface

	for _, combinedPolicy := range combinedPolicies {
		if strings.HasPrefix(combinedPolicy.GetName(), prefix) {
			customerManagedPolicies = append(customerManagedPolicies, combinedPolicy)
		} else {
			awsManagedPolicies = append(awsManagedPolicies, combinedPolicy)
		}
	}

	if len(customerManagedPolicies) > 0 {
		errs := attachCustomerPoliciesHelper(ctx, ssoClient, instanceArn, permissionSetArn, path, customerManagedPolicies)
		unexpectedErrs = append(unexpectedErrs, errs...)
	}

	if len(awsManagedPolicies) > 0 {
		awsManagedArns := make([]string, 0, len(awsManagedPolicies))
		var resolvedArnErrs []error
		for _, awsManagedPolicyArn := range awsManagedPolicies {
			resolvedArn, _, err := getPolicyArnHelper(ctx, iamClient, awsManagedPolicyArn.GetName())
			if err != nil || resolvedArn == "" {
				if err == nil {
					err = fmt.Errorf("policy %q not found", awsManagedPolicyArn.GetName())
				}
				resolvedArnErrs = append(resolvedArnErrs, handleAPIError(err))
				continue
			}
			awsManagedArns = append(awsManagedArns, resolvedArn)
		}

		if len(resolvedArnErrs) > 0 {
			unexpectedErrs = append(unexpectedErrs, resolvedArnErrs...)
		}

		if len(awsManagedArns) > 0 {
			errs := attachAWSManagedPoliciesHelper(ctx, ssoClient, instanceArn, permissionSetArn, awsManagedArns)
			unexpectedErrs = append(unexpectedErrs, errs...)
		}
	}

	if ok, errs := provisionPermissionSetAllWaitHelper(ctx, ssoClient, instanceArn, permissionSetArn, provisionTimeout); !ok {
		unexpectedErrs = append(unexpectedErrs, errs...)
	}

	return unexpectedErrs
}

func detachCustomerPoliciesFromPermissionSetHelper(ctx context.Context, ssoClient *awsSsoAdminClient.Client, permissionSetArn, instanceArn string, combinedPolicies []policyDetailInterface) (unexpectedErrors []error) {
	customerPolicies := map[string]struct{}{}
	for _, combinedPolicy := range combinedPolicies {
		if combinedPolicy.GetName() != "" {
			customerPolicies[combinedPolicy.GetName()] = struct{}{}
		}
	}

	// To ensure the policy has been fully detach, keep on polls the `ListCustomerManagedPolicyReferencesInPermissionSet`
	// until the (Name, Path) reference disappears.
	waitDetachCustomerPoliciesFromPermissionSet := func(name, path string, maxWait time.Duration) error {
		if strings.TrimSpace(path) == "" {
			path = "/"
		}
		listCustomerManagedPolicyReferencesInPermissionSetRequest := func() error {
			listCustomerManagedPolicyReferencesInPermissionSet, err := ssoClient.ListCustomerManagedPolicyReferencesInPermissionSet(ctx,
				&awsSsoAdminClient.ListCustomerManagedPolicyReferencesInPermissionSetInput{
					InstanceArn:      aws.String(instanceArn),
					PermissionSetArn: aws.String(permissionSetArn),
				})
			if err != nil {
				var ae smithy.APIError
				if errors.As(err, &ae) && (ae.ErrorCode() == "NoSuchEntity" || ae.ErrorCode() == "ResourceNotFoundException") {
					return nil
				}
				return err
			}
			for _, reference := range listCustomerManagedPolicyReferencesInPermissionSet.CustomerManagedPolicyReferences {
				referenceName := aws.ToString(reference.Name)
				referencePath := aws.ToString(reference.Path)
				if strings.TrimSpace(referencePath) == "" {
					referencePath = "/"
				}
				if referenceName == name && referencePath == path {
					return fmt.Errorf("policy %s still referenced (path %s)", name, path)
				}
			}
			return nil
		}

		reconnectBackoff := backoff.NewExponentialBackOff()
		reconnectBackoff.MaxElapsedTime = maxWait
		return backoff.Retry(listCustomerManagedPolicyReferencesInPermissionSetRequest, backoff.WithContext(reconnectBackoff, ctx))
	}

	listAndDetachCustomerPoliciesFromPermissionSet := func() error {
		var ae smithy.APIError

		listCustomerManagedPolicyReferencesInPermissionSetRequest, err := ssoClient.ListCustomerManagedPolicyReferencesInPermissionSet(ctx,
			&awsSsoAdminClient.ListCustomerManagedPolicyReferencesInPermissionSetInput{
				InstanceArn:      aws.String(instanceArn),
				PermissionSetArn: aws.String(permissionSetArn),
			})
		if err != nil {
			if errors.As(err, &ae) && (ae.ErrorCode() == "ThrottlingException" || ae.ErrorCode() == "TooManyRequestsException") {
				return err
			}
			return handleAPIError(err)
		}

		for _, ref := range listCustomerManagedPolicyReferencesInPermissionSetRequest.CustomerManagedPolicyReferences {
			if ref.Name == nil {
				continue
			}
			referenceName := aws.ToString(ref.Name)
			actualPath := aws.ToString(ref.Path)
			if strings.TrimSpace(actualPath) == "" {
				actualPath = "/"
			}

			if _, ok := customerPolicies[referenceName]; !ok {
				continue
			}

			_, err := ssoClient.DetachCustomerManagedPolicyReferenceFromPermissionSet(ctx,
				&awsSsoAdminClient.DetachCustomerManagedPolicyReferenceFromPermissionSetInput{
					InstanceArn:      aws.String(instanceArn),
					PermissionSetArn: aws.String(permissionSetArn),
					CustomerManagedPolicyReference: &ssoTypes.CustomerManagedPolicyReference{
						Name: aws.String(referenceName),
						Path: aws.String(actualPath),
					},
				})
			if err != nil {
				if errors.As(err, &ae) {
					switch ae.ErrorCode() {
					case "ResourceNotFoundException", "ConflictException":
						continue
					case "ThrottlingException", "TooManyRequestsException":
						return err
					}
				}
				unexpectedErrors = append(unexpectedErrors, handleAPIError(err))
				continue
			}

			if waitErr := waitDetachCustomerPoliciesFromPermissionSet(referenceName, actualPath, 90*time.Second); waitErr != nil {
				unexpectedErrors = append(unexpectedErrors, waitErr)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(listAndDetachCustomerPoliciesFromPermissionSet, backoff.WithContext(reconnectBackoff, ctx)); err != nil {
		unexpectedErrors = append(unexpectedErrors, err)
	}

	return unexpectedErrors
}
