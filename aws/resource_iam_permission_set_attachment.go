package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsIamClient "github.com/aws/aws-sdk-go-v2/service/iam"
	awsSsoAdminClient "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/smithy-go"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	// Number of 30 indicates the character length of neccessary policy keyword
	// such as "Version" and "Statement" and some JSON symbols ({}, []).
	permissionSetAttachmentKeywordLength = 30
	permissionSetAttachmentMaxLength     = 6144
)

var (
	_ resource.Resource              = &iamPermissionSetAttachmentResource{}
	_ resource.ResourceWithConfigure = &iamPermissionSetAttachmentResource{}
)

func NewIamPermissionSetAttachmentResource() resource.Resource {
	return &iamPermissionSetAttachmentResource{}
}

type iamPermissionSetAttachmentResource struct {
	client *awsIamClient.Client
	sso    *awsSsoAdminClient.Client
}

type iamPermissionSetAttachmentResourceModel struct {
	PermissionSetName      types.String                    `tfsdk:"permission_set_name"`
	InstanceArn            types.String                    `tfsdk:"instance_arn"`
	PermissionSetArn       types.String                    `tfsdk:"permission_set_arn"`
	PolicyPath             types.String                    `tfsdk:"policy_path"`
	AttachedPolicies       types.List                      `tfsdk:"attached_policies"`
	AttachedPoliciesDetail []*iamPermissionSetPolicyDetail `tfsdk:"attached_policies_detail"`
	CombinedPolicesDetail  []*iamPermissionSetPolicyDetail `tfsdk:"combined_policies_detail"`
}

type iamPermissionSetPolicyDetail struct {
	PolicyName     types.String `tfsdk:"policy_name"`
	PolicyDocument types.String `tfsdk:"policy_document"`
}

func (r *iamPermissionSetAttachmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_permission_set_attachment"
}

func (r *iamPermissionSetAttachmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides an IAM Policy resource that manages policy content " +
			"exceeding character limits by splitting it into smaller segments. " +
			"These segments are combined to form a complete policy and attached to the chosen target. " +
			"Policies like `ReadOnlyAccess` that exceed the maximum length are attached directly.",
		Attributes: map[string]schema.Attribute{
			"permission_set_name": schema.StringAttribute{
				Description: "The permission set name.",
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
			"attached_policies": schema.ListAttribute{
				Description: "List of IAM policy.",
				ElementType: types.StringType,
				Required:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
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
		},
	}
}

func (r *iamPermissionSetAttachmentResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(awsClients).iamClient
	r.sso = req.ProviderData.(awsClients).ssoAdminClient
}

func (r *iamPermissionSetAttachmentResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// If the entire plan is null, the resource is planned for destruction.
	if req.Config.Raw.IsNull() {
		fmt.Println("Plan is null; skipping ModifyPlan.")
		return
	}

	var plan *iamPermissionSetAttachmentResourceModel
	if diags := req.Config.Get(ctx, &plan); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Check if PermissionSet block is config. Set default path "/".
	if plan.PolicyPath.IsNull() || plan.PolicyPath.IsUnknown() || plan.PolicyPath.ValueString() == "" {
		plan.PolicyPath = types.StringValue("/") // The default policy path is "/".
	}

}

func (r *iamPermissionSetAttachmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *iamPermissionSetAttachmentResourceModel
	getPlanDiags := req.Config.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policies []string
	plan.AttachedPolicies.ElementsAs(ctx, &policies, false)

	attachedPoliciesDetail, notExistErrList, unexpectedErrList := fetchPoliciesHelper(
		ctx,
		policies,
		func(ctx context.Context, policyName string) (string, string, error) {
			// Call the reusable helper with the struct's client
			return getPolicyArnHelper(ctx, r.client, policyName)
		},
		func(name, doc string) *iamPermissionSetPolicyDetail {
			return &iamPermissionSetPolicyDetail{
				PolicyName:     types.StringValue(name),
				PolicyDocument: types.StringValue(doc),
			}
		},
		r.client,
	)

	errList := append(notExistErrList, unexpectedErrList...)
	if len(errList) != 0 {
		addDiagnostics(
			&resp.Diagnostics,
			"error",
			"[API ERROR] Failed to fetch attached policies.",
			errList,
			"",
		)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	policyDetails := make([]PolicyDetail, len(attachedPoliciesDetail))
	for i := range attachedPoliciesDetail {
		policyDetails[i] = attachedPoliciesDetail[i]
	}

	combinedPolicyDocs, excludedPoliciesInterface, errList2 := combinePolicyDocumentsHelper(
		policyDetails,
		permissionSetAttachmentKeywordLength,
		permissionSetAttachmentMaxLength,
	)
	errList = append(errList, errList2...)

	addDiagnostics(
		&resp.Diagnostics,
		"error",
		"[API ERROR] Failed to combine policy documents.",
		errList,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	excludedPolicies := make([]*iamPermissionSetPolicyDetail, len(excludedPoliciesInterface))
	for i, p := range excludedPoliciesInterface {
		excludedPolicies[i] = p.(*iamPermissionSetPolicyDetail)
	}

	var combinedPolicies []*iamPermissionSetPolicyDetail
	prefix := plan.PermissionSetName.ValueString()
	for i, doc := range combinedPolicyDocs {
		policyName := fmt.Sprintf("%s-%d", prefix, i+1)
		combinedPolicies = append(combinedPolicies, &iamPermissionSetPolicyDetail{
			PolicyName:     types.StringValue(policyName),
			PolicyDocument: types.StringValue(doc),
		})
	}

	combinedPolicies = append(combinedPolicies, excludedPolicies...)

	state := &iamPermissionSetAttachmentResourceModel{
		PermissionSetName:      plan.PermissionSetName,
		InstanceArn:            plan.InstanceArn,
		PermissionSetArn:       plan.PermissionSetArn,
		PolicyPath:             plan.PolicyPath,
		AttachedPolicies:       plan.AttachedPolicies,
		AttachedPoliciesDetail: attachedPoliciesDetail,
		CombinedPolicesDetail:  combinedPolicies,
	}

	combinedPoliciesInterface := make([]policyDetailInterface, len(state.CombinedPolicesDetail))
	for i, p := range state.CombinedPolicesDetail {
		combinedPoliciesInterface[i] = p
	}

	attachErrs := attachPoliciesToPermissionSetHelper(
		ctx,
		r.sso,
		r.client,
		combinedPoliciesInterface,
		state.InstanceArn.ValueString(),
		state.PermissionSetArn.ValueString(),
		state.PermissionSetName.ValueString(),
		state.PolicyPath.ValueString(),
		10*time.Minute,
	)

	if len(attachErrs) > 0 {
		addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to attach policy to target.", attachErrs, "")
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
}

func (r *iamPermissionSetAttachmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state *iamPermissionSetAttachmentResourceModel
	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// This state will be using to compare with the current state.
	var oriState *iamPermissionSetAttachmentResourceModel
	getOriStateDiags := req.State.Get(ctx, &oriState)
	resp.Diagnostics.Append(getOriStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	compareAttachedPoliciesErr := checkPoliciesDriftHelper(state, oriState)
	if compareAttachedPoliciesErr != nil {
		addDiagnostics(
			&resp.Diagnostics,
			"warning",
			fmt.Sprintf("[API WARNING] Policy Drift Detected for %v.", state.PermissionSetName),
			[]error{compareAttachedPoliciesErr},
			"This resource will be updated in the next terraform apply.",
		)
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPermissionSetAttachmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *iamPermissionSetAttachmentResourceModel
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

	removePolicyErr := r.removePolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.PermissionSetName),
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

	var policies []string
	plan.AttachedPolicies.ElementsAs(ctx, &policies, false)

	attachedPoliciesDetail, notExistErrList, unexpectedErrList := fetchPoliciesHelper(
		ctx,
		policies,
		func(ctx context.Context, policyName string) (string, string, error) {
			return getPolicyArnHelper(ctx, r.client, policyName)
		},
		func(name, doc string) *iamPermissionSetPolicyDetail {
			return &iamPermissionSetPolicyDetail{
				PolicyName:     types.StringValue(name),
				PolicyDocument: types.StringValue(doc),
			}
		},
		r.client,
	)

	errList := append(notExistErrList, unexpectedErrList...)
	if len(errList) != 0 {
		addDiagnostics(
			&resp.Diagnostics,
			"error",
			"[API ERROR] Failed to fetch attached policies.",
			errList,
			"",
		)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	policyDetails := make([]PolicyDetail, len(attachedPoliciesDetail))
	for i := range attachedPoliciesDetail {
		policyDetails[i] = attachedPoliciesDetail[i]
	}

	combinedPolicyDocs, excludedPoliciesInterface, errList2 := combinePolicyDocumentsHelper(
		policyDetails,
		policyKeywordLength,
		policyMaxLength,
	)
	errList = append(errList, errList2...)

	addDiagnostics(
		&resp.Diagnostics,
		"error",
		"[API ERROR] Failed to combine policy documents.",
		errList,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}

	excludedPolicies := make([]*iamPermissionSetPolicyDetail, len(excludedPoliciesInterface))
	for i, p := range excludedPoliciesInterface {
		excludedPolicies[i] = p.(*iamPermissionSetPolicyDetail)
	}

	var combinedPolicies []*iamPermissionSetPolicyDetail
	prefix := plan.PermissionSetName.ValueString()
	for i, doc := range combinedPolicyDocs {
		policyName := fmt.Sprintf("%s-%d", prefix, i+1)
		combinedPolicies = append(combinedPolicies, &iamPermissionSetPolicyDetail{
			PolicyName:     types.StringValue(policyName),
			PolicyDocument: types.StringValue(doc),
		})
	}

	combinedPolicies = append(combinedPolicies, excludedPolicies...)

	state = &iamPermissionSetAttachmentResourceModel{
		PermissionSetName:      plan.PermissionSetName,
		InstanceArn:            plan.InstanceArn,
		PermissionSetArn:       plan.PermissionSetArn,
		PolicyPath:             plan.PolicyPath,
		AttachedPolicies:       plan.AttachedPolicies,
		AttachedPoliciesDetail: attachedPoliciesDetail,
		CombinedPolicesDetail:  combinedPolicies,
	}

	combinedPoliciesInterface := make([]policyDetailInterface, len(state.CombinedPolicesDetail))
	for i, p := range state.CombinedPolicesDetail {
		combinedPoliciesInterface[i] = p
	}

	attachErrs := attachPoliciesToPermissionSetHelper(
		ctx,
		r.sso,
		r.client,
		combinedPoliciesInterface,
		state.InstanceArn.ValueString(),
		state.PermissionSetArn.ValueString(),
		state.PermissionSetName.ValueString(),
		state.PolicyPath.ValueString(),
		10*time.Minute,
	)

	if len(attachErrs) > 0 {
		addDiagnostics(&resp.Diagnostics, "error", "[API ERROR] Failed to attach policy to target.", attachErrs, "")
		return
	}
}

func (r *iamPermissionSetAttachmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *iamPermissionSetAttachmentResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// removePolicy.
	removePolicyUnexpectedErr := r.removePolicy(ctx, state)
	addDiagnostics(
		&resp.Diagnostics,
		"error",
		fmt.Sprintf("[API ERROR] Failed to Remove Policies for %v: Unexpected Error!", state.PermissionSetName),
		removePolicyUnexpectedErr,
		"",
	)
	if resp.Diagnostics.HasError() {
		return
	}
}

// removePolicy will detach the combined policies from user.
//
// Parameters:
//   - state: The recorded state configurations.
func (r *iamPermissionSetAttachmentResource) removePolicy(ctx context.Context, state *iamPermissionSetAttachmentResourceModel) (unexpectedError []error) {
	var ae smithy.APIError

	removePolicy := func() error {
		for _, combinedPolicy := range state.CombinedPolicesDetail {
			policyArn, _, err := getPolicyArnHelper(ctx, r.client, combinedPolicy.PolicyName.ValueString())
			if err != nil {
				unexpectedError = append(unexpectedError, err)
				continue
			}

			instanceArn := state.InstanceArn.ValueString()
			psArn := state.PermissionSetArn.ValueString()

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
				policyDetails := make([]policyDetailInterface, len(state.CombinedPolicesDetail))
				for i, p := range state.CombinedPolicesDetail {
					policyDetails[i] = p
				}
				if detErr := errors.Join(
					detachCustomerPoliciesFromPermissionSetHelper(
						ctx,
						r.sso,
						state.PermissionSetArn.ValueString(),
						state.InstanceArn.ValueString(),
						policyDetails,
					)...,
				); detErr != nil {
					return fmt.Errorf("[API ERROR] Failed to detach customer-managed policies from Permission Set: %w", detErr)
				}

			}

			if ok, errs := provisionPermissionSetAllWaitHelper(ctx, r.sso, state.InstanceArn.ValueString(), state.PermissionSetArn.ValueString(), 10*time.Minute); !ok {
				return fmt.Errorf("[API ERROR] Provisioning did not complete: %w", errors.Join(errs...))
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

func (s *iamPermissionSetAttachmentResourceModel) GetAttachedPoliciesDetail() []*policyV2Detail {
	res := make([]*policyV2Detail, len(s.AttachedPoliciesDetail))
	for i, p := range s.AttachedPoliciesDetail {
		res[i] = &policyV2Detail{
			PolicyName:     p.PolicyName,
			PolicyDocument: p.PolicyDocument,
		}
	}
	return res
}

func (s *iamPermissionSetAttachmentResourceModel) SetAttachedPoliciesToNull() {
	s.AttachedPolicies = types.ListNull(types.StringType)
}

func (p *iamPermissionSetPolicyDetail) GetPolicyName() string {
	return p.PolicyName.String()
}
func (p *iamPermissionSetPolicyDetail) GetPolicyDocument() string {
	return p.PolicyDocument.ValueString()
}
