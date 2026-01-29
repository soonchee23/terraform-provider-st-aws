package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsIamClient "github.com/aws/aws-sdk-go-v2/service/iam"
	awsSsoAdminClient "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/smithy-go"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &iamPolicyV2Resource{}
	_ resource.ResourceWithConfigure = &iamPolicyV2Resource{}
)

func NewIamPolicyV2Resource() resource.Resource {
	return &iamPolicyV2Resource{}
}

type iamPolicyV2Resource struct {
	client *awsIamClient.Client
	sso    *awsSsoAdminClient.Client
}

type iamPolicyV2ResourceModel struct {
	PolicyName              types.String        `tfsdk:"policy_name"`
	Role                    *roleBlock          `tfsdk:"role"`
	User                    *userBlock          `tfsdk:"user"`
	PermissionSet           *permissionSetBlock `tfsdk:"permission_set"`
	AttachedPolicies        types.List          `tfsdk:"attached_policies"`
	AttachedPoliciesDetail  []*policyV2Detail   `tfsdk:"attached_policies_detail"`
	CombinedPolicesDetail   []*policyV2Detail   `tfsdk:"combined_policies_detail"`
	AWSManagedPolicies      []*policyV2Detail   `tfsdk:"aws_managed_policies"`
	CustomerManagedPolicies []*policyV2Detail   `tfsdk:"customer_managed_policies"`
}

type roleBlock struct {
	RoleName types.String `tfsdk:"role_name"`
}

type userBlock struct {
	UserName types.String `tfsdk:"user_name"`
}

type permissionSetBlock struct {
	PermissionSetName types.String `tfsdk:"permission_set_name"`
	InstanceArn       types.String `tfsdk:"instance_arn"`
	PermissionSetArn  types.String `tfsdk:"permission_set_arn"`
	PolicyPath        types.String `tfsdk:"policy_path"`
}

type policyV2Detail struct {
	PolicyName     types.String `tfsdk:"policy_name"`
	PolicyDocument types.String `tfsdk:"policy_document"`
}

func (r *iamPolicyV2Resource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_policy_v2"
}

func (r *iamPolicyV2Resource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides an IAM Policy resource that manages policy content " +
			"exceeding character limits by splitting it into smaller segments. " +
			"These segments are combined to form a complete policy and can " +
			"be attached to a specified target if provided. " +
			"Policies like `ReadOnlyAccess` that exceed the maximum length are attached directly.",
		Attributes: map[string]schema.Attribute{
			"policy_name": schema.StringAttribute{
				Description: "The policy name.",
				Optional:    true,
			},
			"attached_policies": schema.ListAttribute{
				Description: "List of IAM policy.",
				ElementType: types.StringType,
				Required:    true,
			},
			"attached_policies_detail": schema.ListNestedAttribute{
				Description: "A list of policies detail.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"policy_name": schema.StringAttribute{
							Description: "The policy name.",
							Computed:    true,
						},
						"policy_document": schema.StringAttribute{
							Description: "The policy document of the IAM policy.",
							Computed:    true,
						},
					},
				},
			},
			"combined_policies_detail": schema.ListNestedAttribute{
				Description: "A list of combined policies that are attached to targets.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"policy_name": schema.StringAttribute{
							Description: "The policy name.",
							Computed:    true,
						},
						"policy_document": schema.StringAttribute{
							Description: "The policy document of the IAM policy.",
							Computed:    true,
						},
					},
				},
			},
			"aws_managed_policies": schema.ListNestedAttribute{
				Description: "A list of combined policies that are attached to targets.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"policy_name": schema.StringAttribute{
							Description: "The policy name.",
							Computed:    true,
						},
						"policy_document": schema.StringAttribute{
							Description: "The policy document of the IAM policy.",
							Computed:    true,
						},
					},
				},
			},
			"customer_managed_policies": schema.ListNestedAttribute{
				Description: "A list of combined policies that are attached to targets.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"policy_name": schema.StringAttribute{
							Description: "The policy name.",
							Computed:    true,
						},
						"policy_document": schema.StringAttribute{
							Description: "The policy document of the IAM policy.",
							Computed:    true,
						},
					},
				},
			},
		},
		Blocks: map[string]schema.Block{
			"role": schema.SingleNestedBlock{
				Description: "Attach to an IAM Role. Mutually exclusive with `user` and `permission_set`.",
				Attributes: map[string]schema.Attribute{
					"role_name": schema.StringAttribute{
						Description: "Target IAM Role name.",
						Optional:    true,
					},
				},
			},
			"user": schema.SingleNestedBlock{
				Description: "Attach to an IAM User. Mutually exclusive with `role` and `permission_set`.",
				Attributes: map[string]schema.Attribute{
					"user_name": schema.StringAttribute{
						Description: "Target IAM User name.",
						Optional:    true,
					},
				},
			},
			"permission_set": schema.SingleNestedBlock{
				Description: "Attach to an Identity Center Permission Set. Mutually exclusive with `role` and `user`.",
				Attributes: map[string]schema.Attribute{
					"permission_set_name": schema.StringAttribute{
						Description: "Logical name for the combined policy attached to the Permission Set.",
						Optional:    true,
					},
					"instance_arn": schema.StringAttribute{
						Description: "Identity Center Instance ARN.",
						Optional:    true,
					},
					"permission_set_arn": schema.StringAttribute{
						Description: "Target Permission Set ARN.",
						Optional:    true,
					},
					"policy_path": schema.StringAttribute{
						Description: "Policy path for customer-managed policy references.",
						Optional:    true,
						Computed:    true,
					},
				},
			},
		},
	}
}

func (r *iamPolicyV2Resource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(awsClients).iamClient
	r.sso = req.ProviderData.(awsClients).ssoAdminClient
}

func (r *iamPolicyV2Resource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// If the entire plan is null, the resource is planned for destruction.
	if req.Config.Raw.IsNull() {
		fmt.Println("Plan is null; skipping ModifyPlan.")
		return
	}

	var plan *iamPolicyV2ResourceModel
	if diags := req.Config.Get(ctx, &plan); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Check if PermissionSet block is config. Set default path "/".
	if plan.PermissionSet != nil {
		if plan.PermissionSet.PolicyPath.IsNull() || plan.PermissionSet.PolicyPath.IsUnknown() || plan.PermissionSet.PolicyPath.ValueString() == "" {
			plan.PermissionSet.PolicyPath = types.StringValue("/") // The default policy path is "/".
		}
	}
}

func (r *iamPolicyV2Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *iamPolicyV2ResourceModel
	getPlanDiags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	combinedPolicies, attachedPolicies, awsManagedPolicies, customerManagedPolicies, errors := r.createPolicy(ctx, plan)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		"[API ERROR] Failed to Create the Policy.",
		errors,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	state := &iamPolicyV2ResourceModel{
		PolicyName:              plan.PolicyName,
		AttachedPolicies:        plan.AttachedPolicies,
		AttachedPoliciesDetail:  attachedPolicies,
		CombinedPolicesDetail:   combinedPolicies,
		AWSManagedPolicies:      awsManagedPolicies,
		CustomerManagedPolicies: customerManagedPolicies,
		Role:                    plan.Role,
		User:                    plan.User,
		PermissionSet:           plan.PermissionSet,
	}

	assigneeType, assigneeName := assigneeTypeOf(plan)

	if plan.Role != nil || plan.User != nil || plan.PermissionSet != nil {
		var attachErrs []error
		switch assigneeType {
		case "role":
			attachErrs = r.attachPolicyToRole(ctx, state)
		case "user":
			attachErrs = r.attachPolicyToUser(ctx, state)
		case "permissionSet":
			var combinedPolicyInterfaces []policyDetailInterface
			for _, p := range state.CombinedPolicesDetail {
				combinedPolicyInterfaces = append(combinedPolicyInterfaces, p)
			}

			attachErrs = attachPoliciesToPermissionSetHelper(
				ctx,
				r.sso,
				r.client,
				combinedPolicyInterfaces,
				state.PermissionSet.InstanceArn.ValueString(),
				state.PermissionSet.PermissionSetArn.ValueString(),
				state.PermissionSet.PermissionSetName.ValueString(),
				state.PermissionSet.PolicyPath.ValueString(),
				10*time.Minute,
			)
		default:
			attachErrs = []error{fmt.Errorf("no valid target (role/user/permission_set) in plan")}
		}
		if len(attachErrs) > 0 {
			addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Attach Policy to target.", attachErrs, "")
			return
		}
	}

	// Create policy are not expected to have not found warning.
	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addReadDiagsWithNotFoundError(&resp.Diagnostics, assigneeName, readCombinedPolicyNotExistErr, readCombinedPolicyErr)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyV2Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state *iamPolicyV2ResourceModel
	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// This state will be using to compare with the current state.
	var oriState *iamPolicyV2ResourceModel
	getOriStateDiags := req.State.Get(ctx, &oriState)
	resp.Diagnostics.Append(getOriStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, assigneeName := assigneeTypeOf(state)

	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addReadDiagsWithNotFoundWarning(&resp.Diagnostics, assigneeName, readCombinedPolicyNotExistErr, readCombinedPolicyErr, "The combined policies may be deleted due to human mistake or API error, will trigger update to recreate the combined policy:")
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state so that Terraform will trigger update if there are changes in state.
	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.WarningsCount() > 0 || resp.Diagnostics.HasError() {
		return
	}

	// If the attached policy not found, it should return warning instead of error
	// because there is no ways to get plan configuration in Read() function to
	// indicate user had removed the non existed policies from the input.
	readAttachedPolicyNotExistErr, readAttachedPolicyErr := r.readAttachedPolicy(ctx, state)
	addReadDiagsWithNotFoundWarning(&resp.Diagnostics, assigneeName, readAttachedPolicyNotExistErr, readAttachedPolicyErr, "The policy that will be used to combine policies had been removed on AWS, next apply with update will prompt error:")

	// Set state so that Terraform will trigger update if there are changes in state.
	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.WarningsCount() > 0 || resp.Diagnostics.HasError() {
		return
	}

	compareAttachedPoliciesErr := checkPoliciesDriftHelper(state, oriState)
	addDiagnostics(
		&resp.Diagnostics,
		"warning",
		fmt.Sprintf("[API WARNING] Policy Drift Detected for %v.", assigneeName),
		[]error{compareAttachedPoliciesErr},
		"This resource will be updated in the next terraform apply.",
	)

	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read the attached policy. -> If got changes, remove policy. -> Create the policy again. -> Attach to the targets.
func (r *iamPolicyV2Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *iamPolicyV2ResourceModel
	getPlanDiags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, assigneeName := assigneeTypeOf(state)

	// readAttachedPolicy.
	readAttachedPolicyNotExistErr, readAttachedPolicyErr := r.readAttachedPolicy(ctx, plan)
	addReadDiagsWithNotFoundError(&resp.Diagnostics, assigneeName, readAttachedPolicyNotExistErr, readAttachedPolicyErr)
	if resp.Diagnostics.HasError() {
		return
	}

	// removePolicy.
	removePolicyErr := r.removePolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", assigneeName),
		removePolicyErr,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	state.CombinedPolicesDetail = nil
	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// createPolicy.
	combinedPolicies, attachedPolicies, awsManagedPolicies, customerManagedPolicies, errors := r.createPolicy(ctx, plan)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		"[API ERROR] Failed to Create the Policy.",
		errors,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	state = &iamPolicyV2ResourceModel{
		PolicyName:              plan.PolicyName,
		AttachedPolicies:        plan.AttachedPolicies,
		AttachedPoliciesDetail:  attachedPolicies,
		CombinedPolicesDetail:   combinedPolicies,
		AWSManagedPolicies:      awsManagedPolicies,
		CustomerManagedPolicies: customerManagedPolicies,
		Role:                    plan.Role,
		User:                    plan.User,
		PermissionSet:           plan.PermissionSet,
	}

	assigneeType, assigneeName := assigneeTypeOf(plan)
	if plan.Role != nil || plan.User != nil || plan.PermissionSet != nil {
		var attachPolicyToUserErr []error
		switch assigneeType {
		case "role":
			attachPolicyToUserErr = r.attachPolicyToRole(ctx, state)
		case "user":
			attachPolicyToUserErr = r.attachPolicyToUser(ctx, state)
		case "permissionSet":
			var combinedPolicyInterfaces []policyDetailInterface
			for _, p := range state.CombinedPolicesDetail {
				combinedPolicyInterfaces = append(combinedPolicyInterfaces, p)
			}

			attachPolicyToUserErr = attachPoliciesToPermissionSetHelper(
				ctx,
				r.sso,
				r.client,
				combinedPolicyInterfaces,
				state.PermissionSet.InstanceArn.ValueString(),
				state.PermissionSet.PermissionSetArn.ValueString(),
				state.PermissionSet.PermissionSetName.ValueString(),
				state.PermissionSet.PolicyPath.ValueString(),
				10*time.Minute,
			)
		default:
			attachPolicyToUserErr = []error{fmt.Errorf("no valid target (role/user/permission_set) in plan")}
		}
		if len(attachPolicyToUserErr) > 0 {
			addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to Attach Policy to target.", attachPolicyToUserErr, "")
			return
		}
	}

	readCombinedPolicyNotExistErr, readCombinedPolicyErr := r.readCombinedPolicy(ctx, state)
	addReadDiagsWithNotFoundError(&resp.Diagnostics, assigneeName, readCombinedPolicyNotExistErr, readCombinedPolicyErr)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyV2Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *iamPolicyV2ResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// removePolicy.
	removePolicyErr := r.removePolicy(ctx, state)
	_, removePolicyName := assigneeTypeOf(state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", removePolicyName),
		removePolicyErr,
		"",
	)
	if resp.Diagnostics.HasError() {

		return
	}
}

// createPolicy will create the combined policy and return the attached policies
// details to be saved in state for comparing in Read() function.
//
// Parameters:
//   - ctx: Context.
//   - plan: Terraform plan configurations.
//
// Returns:
//   - combinedPoliciesDetail: The combined policies detail to be recorded in state file.
//   - attachedPoliciesDetail: The attached policies detail to be recorded in state file.
//   - errList: List of errors, return nil if no errors.
func (r *iamPolicyV2Resource) createPolicy(ctx context.Context, plan *iamPolicyV2ResourceModel) (combinedPoliciesDetail []*policyV2Detail, attachedPoliciesDetail []*policyV2Detail, awsManagedPolicies []*policyV2Detail, customerManagedPolicies []*policyV2Detail, errList []error) {
	var policies []string
	plan.AttachedPolicies.ElementsAs(ctx, &policies, false)

	attachedPoliciesDetail, notExistErrList, unexpectedErrList := fetchPoliciesHelper(
		ctx,
		policies,
		func(ctx context.Context, policyName string) (string, string, error) {
			return getPolicyArnHelper(ctx, r.client, policyName)
		},
		func(name, doc string) *policyV2Detail {
			return &policyV2Detail{
				PolicyName:     types.StringValue(name),
				PolicyDocument: types.StringValue(doc),
			}
		},
		r.client,
	)

	errList = append(notExistErrList, unexpectedErrList...)
	if len(errList) != 0 {
		return nil, nil, nil, nil, errList
	}

	policyDetails := make([]PolicyDetail, len(attachedPoliciesDetail))
	for i := range attachedPoliciesDetail {
		policyDetails[i] = attachedPoliciesDetail[i]
	}

	combinedPolicyDocuments, excludedPoliciesInterface, errList2 := combinePolicyDocumentsHelper(
		policyDetails,
		policyKeywordLength,
		policyMaxLength,
	)

	errList = append(errList, errList2...)
	if errList != nil {
		return nil, nil, nil, nil, errList
	}

	excludedPolicies := make([]*policyV2Detail, len(excludedPoliciesInterface))
	for i, p := range excludedPoliciesInterface {
		excludedPolicies[i] = p.(*policyV2Detail)
	}

	assigneeType, prefix := assigneeTypeOf(plan)
	pathPtr := (*string)(nil)
	usePath := false

	if assigneeType == "permissionSet" &&
		plan.PermissionSet != nil &&
		plan.PermissionSet.PolicyPath.ValueString() != "" {

		path := plan.PermissionSet.PolicyPath.ValueString()
		pathPtr = &path
		usePath = true
	}

	createPolicy := func() error {
		for i, policy := range combinedPolicyDocuments {
			policyName := fmt.Sprintf("%s-%d", prefix, i+1)

			createPolicyRequest := &awsIamClient.CreatePolicyInput{
				PolicyName:     aws.String(policyName),
				PolicyDocument: aws.String(policy),
			}
			if usePath {
				createPolicyRequest.Path = pathPtr
			}

			if _, err := r.client.CreatePolicy(ctx, createPolicyRequest); err != nil {
				return handleAPIError(err)
			}
		}

		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err := backoff.Retry(createPolicy, reconnectBackoff)

	if err != nil {
		return nil, nil, nil, nil, []error{err}
	}

	for i, policies := range combinedPolicyDocuments {
		policyName := fmt.Sprintf("%s-%d", prefix, i+1)

		combinedPoliciesDetail = append(combinedPoliciesDetail, &policyV2Detail{
			PolicyName:     types.StringValue(policyName),
			PolicyDocument: types.StringValue(policies),
		})

		// To seperate the customer managed policies.
		customerManagedPolicies = append(customerManagedPolicies, &policyV2Detail{
			PolicyName:     types.StringValue(policyName),
			PolicyDocument: types.StringValue(policies),
		})
	}

	// These policies will be attached directly to the user since splitting the
	// policy "statement" will be hitting the limitation of "maximum number of
	// attached policies" easily.
	combinedPoliciesDetail = append(combinedPoliciesDetail, excludedPolicies...)
	// To seperate AWS managed policies.
	awsManagedPolicies = append(awsManagedPolicies, excludedPolicies...)

	return combinedPoliciesDetail, attachedPoliciesDetail, awsManagedPolicies, customerManagedPolicies, nil
}

// readCombinedPolicy will read the combined policy details.
//
// Parameters:
//   - state: The state configurations, it will directly update the value of the struct since it is a pointer.
//
// Returns:
//   - notExistError: List of allowed not exist errors to be used as warning messages instead, return nil if no errors.
//   - unexpectedError: List of unexpected errors to be used as normal error messages, return nil if no errors.
func (r *iamPolicyV2Resource) readCombinedPolicy(ctx context.Context, state *iamPolicyV2ResourceModel) (notExistErrs, unexpectedErrs []error) {
	var policiesName []string
	for _, policy := range state.CombinedPolicesDetail {
		policiesName = append(policiesName, policy.PolicyName.ValueString())
	}

	policyDetails, notExistErrs, unexpectedErrs := fetchPoliciesHelper(
		ctx,
		policiesName,
		func(ctx context.Context, policyName string) (string, string, error) {
			return getPolicyArnHelper(ctx, r.client, policyName)
		},
		func(name, doc string) *policyV2Detail {
			return &policyV2Detail{
				PolicyName:     types.StringValue(name),
				PolicyDocument: types.StringValue(doc),
			}
		},
		r.client,
	)

	if len(unexpectedErrs) > 0 {
		return nil, unexpectedErrs
	}

	// If the combined policies not found from AWS, that it might be deleted
	// from outside Terraform. Set the state to Unknown to trigger state changes
	// and Update() function.
	if len(notExistErrs) > 0 {
		// This is to ensure Update() is called.
		state.AttachedPolicies = types.ListNull(types.StringType)
	}

	state.CombinedPolicesDetail = policyDetails
	return notExistErrs, nil
}

// readAttachedPolicy will read the attached policy details.
//
// Parameters:
//   - state: The state configurations, it will directly update the value of the struct since it is a pointer.
//
// Returns:
//   - notExistError: List of allowed not exist errors to be used as warning messages instead, return nil if no errors.
//   - unexpectedError: List of unexpected errors to be used as normal error messages, return nil if no errors.
func (r *iamPolicyV2Resource) readAttachedPolicy(ctx context.Context, state *iamPolicyV2ResourceModel) (notExistErrs, unexpectedErrs []error) {
	var policiesName []string
	for _, policyName := range state.AttachedPolicies.Elements() {
		policiesName = append(policiesName, strings.Trim(policyName.String(), "\""))
	}

	policyDetails, notExistErrs, unexpectedErrs := fetchPoliciesHelper(
		ctx,
		policiesName,
		func(ctx context.Context, policyName string) (string, string, error) {
			// Wrap the generic helper with the struct's client
			return getPolicyArnHelper(ctx, r.client, policyName)
		},
		func(name, doc string) *policyV2Detail {
			return &policyV2Detail{
				PolicyName:     types.StringValue(name),
				PolicyDocument: types.StringValue(doc),
			}
		},
		r.client,
	)

	if len(unexpectedErrs) > 0 {
		return nil, unexpectedErrs
	}

	// If the combined policies not found from AWS, that it might be deleted
	// from outside Terraform. Set the state to Unknown to trigger state changes
	// and Update() function.
	if len(notExistErrs) > 0 {
		// This is to ensure Update() is called.
		state.AttachedPolicies = types.ListNull(types.StringType)
	}

	state.AttachedPoliciesDetail = policyDetails
	return notExistErrs, nil
}

// removePolicy will detach and delete the combined policies from user.
//
// Parameters:
//   - state: The recorded state configurations.
func (r *iamPolicyV2Resource) removePolicy(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	var ae smithy.APIError
	var listPolicyVersionsResponse *awsIamClient.ListPolicyVersionsOutput

	removePolicy := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := getPolicyArnHelper(ctx, r.client, combinedPolicy.PolicyName.ValueString())
			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			switch {
			case state.Role != nil:

				if _, err := r.client.DetachRolePolicy(ctx, &awsIamClient.DetachRolePolicyInput{
					PolicyArn: aws.String(policyArn),
					RoleName:  aws.String(state.Role.RoleName.ValueString()),
				}); err != nil && !(errors.As(err, &ae) && ae.ErrorCode() == "NoSuchEntity") {
					return handleAPIError(err)
				}

			case state.User != nil:

				if _, err := r.client.DetachUserPolicy(ctx, &awsIamClient.DetachUserPolicyInput{
					PolicyArn: aws.String(policyArn),
					UserName:  aws.String(state.User.UserName.ValueString()),
				}); err != nil && !(errors.As(err, &ae) && ae.ErrorCode() == "NoSuchEntity") {
					return handleAPIError(err)
				}

			case state.PermissionSet != nil:

				instanceArn := state.PermissionSet.InstanceArn.ValueString()
				psArn := state.PermissionSet.PermissionSetArn.ValueString()

				a, err := arn.Parse(policyArn)
				if err != nil {
					continue
				}

				if a.AccountID == "aws" {
					if _, err := r.sso.DetachManagedPolicyFromPermissionSet(ctx, &awsSsoAdminClient.DetachManagedPolicyFromPermissionSetInput{
						InstanceArn:      aws.String(instanceArn),
						PermissionSetArn: aws.String(psArn),
						ManagedPolicyArn: aws.String(policyArn),
					}); err != nil {
						if errors.As(err, &ae) {
							if ae.ErrorCode() == "ResourceNotFoundException" || ae.ErrorCode() == "ValidationException" {
							} else {
								return handleAPIError(err)
							}
						} else {
							return handleAPIError(err)
						}
					}
				} else {
					// Customer-managed: convert to interface for helper
					policyDetails := make([]policyDetailInterface, len(state.CombinedPolicesDetail))
					for i, p := range state.CombinedPolicesDetail {
						policyDetails[i] = p
					}

					if detErr := errors.Join(
						detachCustomerPoliciesFromPermissionSetHelper(
							ctx,
							r.sso,
							psArn,
							instanceArn,
							policyDetails,
						)...,
					); detErr != nil {
						return fmt.Errorf("[API ERROR] Failed to detach customer-managed policies from Permission Set: %w", detErr)
					}
				}

				if ok, errs := provisionPermissionSetAllWaitHelper(ctx, r.sso, state.PermissionSet.InstanceArn.ValueString(), state.PermissionSet.PermissionSetArn.ValueString(), 10*time.Minute); !ok {
					return fmt.Errorf("[API ERROR] Provisioning did not complete: %w", errors.Join(errs...))
				}

			}

			a, err := arn.Parse(policyArn)
			if err != nil {
				continue
			}

			// The arn difference between AWS managed policy and customer managed policies:
			// AWS managed policy: arn:aws:iam::*aws*:policy/XxxxXxxxx
			// Customer managed policy: arn:aws:iam::*xxxxxxxxxxxx*:policy/xxxx-xxx-xxxx-xxxx-xxx-xx
			// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html for more information.
			// To differentiate is the ** part, the part is AccountID field.
			if a.AccountID == "aws" {
				continue
			}

			listPolicyVersionsRequest := &awsIamClient.ListPolicyVersionsInput{
				PolicyArn: aws.String(policyArn),
			}

			// An IAM policy versions must be removed before deleting
			// the policy. Refer to the below offcial IAM documents:
			// https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeletePolicy.html
			if listPolicyVersionsResponse, err = r.client.ListPolicyVersions(ctx, listPolicyVersionsRequest); err != nil {
				if errors.As(err, &ae) {
					// Ignore error where the policy version does
					// not exists in the policy as it was intended
					// to delete the policy version.
					if ae.ErrorCode() != "NoSuchEntity" {
						return handleAPIError(err)
					}
				}
			}

			for _, policyVersion := range listPolicyVersionsResponse.Versions {
				// Default version could not be deleted.
				if policyVersion.IsDefaultVersion {
					continue
				}
				deletePolicyVersionRequest := &awsIamClient.DeletePolicyVersionInput{
					PolicyArn: aws.String(policyArn),
					VersionId: aws.String(*policyVersion.VersionId),
				}

				if _, err = r.client.DeletePolicyVersion(ctx, deletePolicyVersionRequest); err != nil {
					// Ignore error where the policy version does
					// not exists in the policy as it was intended
					// to delete the policy version.
					if errors.As(err, &ae) && ae.ErrorCode() != "NoSuchEntity" {
						return handleAPIError(err)
					}
				}
			}

			deletePolicyRequest := &awsIamClient.DeletePolicyInput{
				PolicyArn: aws.String(policyArn),
			}

			if _, err = r.client.DeletePolicy(ctx, deletePolicyRequest); err != nil {
				// Ignore error where the policy had been deleted
				// as it is intended to delete the IAM policy.
				if errors.As(err, &ae) && ae.ErrorCode() != "NoSuchEntity" {
					return handleAPIError(err)
				}
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err := backoff.Retry(removePolicy, reconnectBackoff)
	if err != nil {
		return append(unexpectedError, err)
	}

	return nil
}

// attachPolicyToRole attach the IAM policy to role through AWS SDK.
//
// Parameters:
//   - state: The recorded state configurations.
//
// Returns:
//   - err: Error.
func (r *iamPolicyV2Resource) attachPolicyToRole(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	attachPolicyToRole := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := getPolicyArnHelper(ctx, r.client, combinedPolicy.PolicyName.ValueString())
			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			attachPolicyToRoleRequest := &awsIamClient.AttachRolePolicyInput{
				PolicyArn: aws.String(policyArn),
				RoleName:  aws.String(state.Role.RoleName.ValueString()),
			}

			if _, err := r.client.AttachRolePolicy(ctx, attachPolicyToRoleRequest); err != nil {
				return handleAPIError(err)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachPolicyToRole, reconnectBackoff); err != nil {
		unexpectedError = append(unexpectedError, err)
	}

	return unexpectedError
}

// attachPolicyToUser attach the IAM policy to user through AWS SDK.
//
// Parameters:
//   - state: The recorded state configurations.
//
// Returns:
//   - err: Error.
func (r *iamPolicyV2Resource) attachPolicyToUser(ctx context.Context, state *iamPolicyV2ResourceModel) (unexpectedError []error) {
	attachPolicyToUser := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := getPolicyArnHelper(ctx, r.client, combinedPolicy.PolicyName.ValueString())

			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			attachPolicyToUserRequest := &awsIamClient.AttachUserPolicyInput{
				PolicyArn: aws.String(policyArn),
				UserName:  aws.String(state.User.UserName.ValueString()),
			}

			if _, err := r.client.AttachUserPolicy(ctx, attachPolicyToUserRequest); err != nil {
				return handleAPIError(err)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	if err := backoff.Retry(attachPolicyToUser, reconnectBackoff); err != nil {
		unexpectedError = append(unexpectedError, err)
	}

	return unexpectedError
}

func assigneeTypeOf(assignee *iamPolicyV2ResourceModel) (assigneeType string, assigneeName string) {
	if assignee == nil {
		return "", "(unknown-target)"
	}
	if !assignee.PolicyName.IsNull() {
		return "noAssignee", assignee.PolicyName.ValueString()
	}
	if assignee.Role != nil && !assignee.Role.RoleName.IsNull() && !assignee.Role.RoleName.IsUnknown() && assignee.Role.RoleName.ValueString() != "" {
		return "role", assignee.Role.RoleName.ValueString()
	}
	if assignee.User != nil && !assignee.User.UserName.IsNull() && !assignee.User.UserName.IsUnknown() && assignee.User.UserName.ValueString() != "" {
		return "user", assignee.User.UserName.ValueString()
	}
	if assignee.PermissionSet != nil && !assignee.PermissionSet.PermissionSetName.IsNull() && !assignee.PermissionSet.PermissionSetName.IsUnknown() && assignee.PermissionSet.PermissionSetName.ValueString() != "" {
		return "permissionSet", assignee.PermissionSet.PermissionSetName.ValueString()
	}
	return "", "(unknown-target)"
}

// addReadDiagsWithNotFoundWarning adds diagnostic messages when reading attached policies fails.
//   - Policies that are not found on AWS generate a WARNING instead of an ERROR, indicating that
//     the policy has been removed externally and a future apply may fail.
//   - Unexpected errors (e.g., API failures) still generate an ERROR.
func addReadDiagsWithNotFoundWarning(diags *diag.Diagnostics, assigneeName string, notFoundErrs, unexpectedErrs []error, warningDetail string,) {
	addDiagnostics(
		diags, "warning",
		fmt.Sprintf("[API WARNING] Failed to Read Attached Policies for %v: Policy Not Found!", assigneeName),
		notFoundErrs, warningDetail,
	)
	addDiagnostics(
		diags, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", assigneeName),
		unexpectedErrs, "",
	)
}

// addReadDiagsWithNotFoundError adds diagnostic messages when reading attached policies fails.
// - Policies that are not found on AWS generate an ERROR, preventing the user from applying a non-existent policy.
// - Unexpected errors (e.g., API failures) also generate an ERROR.
func addReadDiagsWithNotFoundError(diags *diag.Diagnostics, assigneeName string, notFoundErrs, unexpectedErrs []error) {
	addDiagnostics(
		diags, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Policy Not Found!", assigneeName),
		notFoundErrs, "",
	)
	addDiagnostics(
		diags, "error",
		fmt.Sprintf("[API ERROR] Failed to Read Combined Policies for %v: Unexpected Error!", assigneeName),
		unexpectedErrs, "",
	)
}

func (s *iamPolicyV2ResourceModel) GetAttachedPoliciesDetail() []*policyV2Detail {
	res := make([]*policyV2Detail, len(s.AttachedPoliciesDetail))
	for i, p := range s.AttachedPoliciesDetail {
		res[i] = &policyV2Detail{
			PolicyName:     p.PolicyName,
			PolicyDocument: p.PolicyDocument,
		}
	}
	return res
}

func (s *iamPolicyV2ResourceModel) SetAttachedPoliciesToNull() {
	s.AttachedPolicies = types.ListNull(types.StringType)
}

func (p *policyV2Detail) GetPolicyName() string {
	return p.PolicyName.String()
}

func (p *policyV2Detail) GetPolicyDocument() string {
	return p.PolicyDocument.ValueString()
}
