package internal

import (
	"context"
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/structpb"
)

func casbinModuleConfigToMap(cfg *contracts.CasbinModuleConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	out := compactMap(map[string]any{
		"model": cfg.GetModel(),
	})
	if policies := stringListsToAny(cfg.GetPolicies()); len(policies) > 0 {
		out["policies"] = policies
	}
	if assignments := stringListsToAny(cfg.GetRoleAssignments()); len(assignments) > 0 {
		out["roleAssignments"] = assignments
	}
	if adapter := cfg.GetAdapter(); adapter != nil {
		out["adapter"] = compactMap(map[string]any{
			"type":         adapter.GetType(),
			"path":         adapter.GetPath(),
			"driver":       adapter.GetDriver(),
			"dsn":          adapter.GetDsn(),
			"table_name":   adapter.GetTableName(),
			"tenant":       adapter.GetTenant(),
			"filter_field": adapter.GetFilterField(),
			"filter_value": adapter.GetFilterValue(),
		})
	}
	if watcher := cfg.GetWatcher(); watcher != nil {
		out["watcher"] = compactMap(map[string]any{
			"type":     watcher.GetType(),
			"interval": watcher.GetInterval(),
		})
	}
	return out
}

func permitModuleConfigToMap(cfg *contracts.PermitModuleConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{
		"apiKey":      cfg.GetApiKey(),
		"pdpUrl":      cfg.GetPdpUrl(),
		"apiUrl":      cfg.GetApiUrl(),
		"project":     cfg.GetProject(),
		"environment": cfg.GetEnvironment(),
	})
}

func typedAuthzCheck(registry moduleRegistry) sdk.TypedStepHandler[*contracts.AuthzCheckConfig, *contracts.AuthzCheckInput, *contracts.AuthzCheckOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.AuthzCheckConfig, *contracts.AuthzCheckInput]) (*sdk.TypedStepResult[*contracts.AuthzCheckOutput], error) {
		cfg := authzCheckConfigToMap(req.Config)
		cfg = mergeStringFields(cfg, authzCheckInputToMap(req.Input))
		step, err := newAuthzCheckStep("typed", cfg)
		if err != nil {
			return nil, err
		}
		step.registry = registry
		current := copyMap(req.Current)
		if subject := req.Input.GetSubject(); subject != "" {
			subjectKey := step.subjectKey
			current[subjectKey] = subject
		}
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, current, req.Metadata, nil)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.AuthzCheckOutput]{Output: authzCheckOutputFromMap(result.Output), StopPipeline: result.StopPipeline}, nil
	}
}

func typedAuthzAddPolicy(registry moduleRegistry) sdk.TypedStepHandler[*contracts.PolicyRuleConfig, *contracts.PolicyRuleInput, *contracts.PolicyRuleOutput] {
	return typedPolicyRule(registry, wrapStepConstructor(newAuthzAddPolicyStep), "authz_policy_added")
}

func typedAuthzRemovePolicy(registry moduleRegistry) sdk.TypedStepHandler[*contracts.PolicyRuleConfig, *contracts.PolicyRuleInput, *contracts.PolicyRuleOutput] {
	return typedPolicyRule(registry, wrapStepConstructor(newAuthzRemovePolicyStep), "authz_policy_removed")
}

func typedAuthzABACAddPolicy(registry moduleRegistry) sdk.TypedStepHandler[*contracts.PolicyRuleConfig, *contracts.PolicyRuleInput, *contracts.PolicyRuleOutput] {
	return typedPolicyRule(registry, wrapStepConstructor(newAuthzABACAddPolicyStep), "policy_added")
}

func typedPolicyRule(registry moduleRegistry, create func(string, map[string]any) (sdk.StepInstance, error), changedKey string) sdk.TypedStepHandler[*contracts.PolicyRuleConfig, *contracts.PolicyRuleInput, *contracts.PolicyRuleOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.PolicyRuleConfig, *contracts.PolicyRuleInput]) (*sdk.TypedStepResult[*contracts.PolicyRuleOutput], error) {
		cfg := mergeStringFields(policyRuleConfigToMap(req.Config), policyRuleInputToMap(req.Input))
		step, err := create("typed", cfg)
		if err != nil {
			return nil, err
		}
		switch s := step.(type) {
		case *authzAddPolicyStep:
			s.registry = registry
		case *authzRemovePolicyStep:
			s.registry = registry
		case *authzABACAddPolicyStep:
			s.registry = registry
		}
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, req.Current, req.Metadata, nil)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.PolicyRuleOutput]{Output: policyRuleOutputFromMap(result.Output, changedKey)}, nil
	}
}

func typedAuthzRoleAssign(registry moduleRegistry) sdk.TypedStepHandler[*contracts.RoleAssignConfig, *contracts.RoleAssignInput, *contracts.RoleAssignOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.RoleAssignConfig, *contracts.RoleAssignInput]) (*sdk.TypedStepResult[*contracts.RoleAssignOutput], error) {
		cfg := mergeStringFields(roleAssignConfigToMap(req.Config), roleAssignInputToMap(req.Input))
		step, err := newAuthzRoleAssignStep("typed", cfg)
		if err != nil {
			return nil, err
		}
		step.registry = registry
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, req.Current, req.Metadata, nil)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.RoleAssignOutput]{Output: roleAssignOutputFromMap(result.Output)}, nil
	}
}

func typedAuthzCapabilities(registry moduleRegistry) sdk.TypedStepHandler[*contracts.CapabilitiesConfig, *contracts.CapabilitiesInput, *contracts.CapabilitiesOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.CapabilitiesConfig, *contracts.CapabilitiesInput]) (*sdk.TypedStepResult[*contracts.CapabilitiesOutput], error) {
		cfg := mergeStringFields(capabilitiesConfigToMap(req.Config), capabilitiesInputToMap(req.Input))
		step, err := newAuthzCapabilitiesStep("typed", cfg)
		if err != nil {
			return nil, err
		}
		step.registry = registry
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, req.Current, req.Metadata, nil)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.CapabilitiesOutput]{Output: capabilitiesOutputFromMap(result.Output)}, nil
	}
}

func typedSubjectObjectAction(create func(string, map[string]any) (sdk.StepInstance, error), registry moduleRegistry) sdk.TypedStepHandler[*contracts.SubjectObjectActionConfig, *contracts.SubjectObjectActionInput, *contracts.SubjectObjectActionOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.SubjectObjectActionConfig, *contracts.SubjectObjectActionInput]) (*sdk.TypedStepResult[*contracts.SubjectObjectActionOutput], error) {
		cfg := mergeStringFields(subjectObjectActionConfigToMap(req.Config), subjectObjectActionInputToMap(req.Input))
		step, err := create("typed", cfg)
		if err != nil {
			return nil, err
		}
		setStepRegistry(step, registry)
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, req.Current, req.Metadata, nil)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.SubjectObjectActionOutput]{Output: subjectObjectActionOutputFromMap(result.Output)}, nil
	}
}

func typedList(create func(string, map[string]any) (sdk.StepInstance, error), registry moduleRegistry) sdk.TypedStepHandler[*contracts.ListConfig, *contracts.ListInput, *contracts.GenericStepOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.ListConfig, *contracts.ListInput]) (*sdk.TypedStepResult[*contracts.GenericStepOutput], error) {
		cfg := mergeStringFields(listConfigToMap(req.Config), listInputToMap(req.Input))
		step, err := create("typed", cfg)
		if err != nil {
			return nil, err
		}
		setStepRegistry(step, registry)
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, req.Current, req.Metadata, nil)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.GenericStepOutput]{Output: genericOutputFromMap(result.Output), StopPipeline: result.StopPipeline}, nil
	}
}

func typedRelation(create func(string, map[string]any) (sdk.StepInstance, error), registry moduleRegistry) sdk.TypedStepHandler[*contracts.RelationConfig, *contracts.RelationInput, *contracts.RelationOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.RelationConfig, *contracts.RelationInput]) (*sdk.TypedStepResult[*contracts.RelationOutput], error) {
		cfg := mergeStringFields(relationConfigToMap(req.Config), relationInputToMap(req.Input))
		step, err := create("typed", cfg)
		if err != nil {
			return nil, err
		}
		setStepRegistry(step, registry)
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, req.Current, req.Metadata, nil)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.RelationOutput]{Output: relationOutputFromMap(result.Output)}, nil
	}
}

func typedPermitStep(typeName string) sdk.TypedStepHandler[*contracts.PermitStepConfig, *contracts.PermitStepInput, *contracts.GenericStepOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.PermitStepConfig, *contracts.PermitStepInput]) (*sdk.TypedStepResult[*contracts.GenericStepOutput], error) {
		cfg := permitStepConfigToMap(req.Config)
		cfg = mergeStringFields(cfg, permitStepInputToMap(req.Input))
		step, err := createPermitStep(typeName, "typed", cfg)
		if err != nil {
			return nil, err
		}
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, req.Current, req.Metadata, cfg)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.GenericStepOutput]{Output: genericOutputFromMap(result.Output), StopPipeline: result.StopPipeline}, nil
	}
}

func setStepRegistry(step sdk.StepInstance, registry moduleRegistry) {
	switch s := step.(type) {
	case *authzACLGrantStep:
		s.registry = registry
	case *authzACLRevokeStep:
		s.registry = registry
	case *authzACLCheckStep:
		s.registry = registry
	case *authzACLListStep:
		s.registry = registry
	case *authzABACCheckStep:
		s.registry = registry
	case *authzReBACAddRelationStep:
		s.registry = registry
	case *authzReBACRemoveRelationStep:
		s.registry = registry
	case *authzReBACCheckStep:
		s.registry = registry
	case *authzReBACListRelationsStep:
		s.registry = registry
	}
}

func authzCheckConfigToMap(cfg *contracts.AuthzCheckConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	out := compactMap(map[string]any{
		"module":      cfg.GetModule(),
		"subject_key": cfg.GetSubjectKey(),
		"object":      cfg.GetObject(),
		"action":      cfg.GetAction(),
	})
	if cfg.GetAudit() {
		out["audit"] = true
	}
	if fields := extraFieldsToAny(cfg.GetExtraFields()); len(fields) > 0 {
		out["extra_fields"] = fields
	}
	return out
}

func authzCheckInputToMap(input *contracts.AuthzCheckInput) map[string]any {
	if input == nil {
		return nil
	}
	out := compactMap(map[string]any{
		"module":      input.GetModule(),
		"subject_key": input.GetSubjectKey(),
		"object":      input.GetObject(),
		"action":      input.GetAction(),
	})
	if fields := extraFieldsToAny(input.GetExtraFields()); len(fields) > 0 {
		out["extra_fields"] = fields
	}
	return out
}

func policyRuleConfigToMap(cfg *contracts.PolicyRuleConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	out := compactMap(map[string]any{"module": cfg.GetModule()})
	if len(cfg.GetRule()) > 0 {
		out["rule"] = stringsToAny(cfg.GetRule())
	}
	return out
}

func policyRuleInputToMap(input *contracts.PolicyRuleInput) map[string]any {
	if input == nil {
		return nil
	}
	out := compactMap(map[string]any{"module": input.GetModule()})
	if len(input.GetRule()) > 0 {
		out["rule"] = stringsToAny(input.GetRule())
	}
	return out
}

func roleAssignConfigToMap(cfg *contracts.RoleAssignConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	out := compactMap(map[string]any{"module": cfg.GetModule(), "action": cfg.GetAction()})
	if assignments := stringListsToAny(cfg.GetAssignments()); len(assignments) > 0 {
		out["assignments"] = assignments
	}
	return out
}

func roleAssignInputToMap(input *contracts.RoleAssignInput) map[string]any {
	if input == nil {
		return nil
	}
	out := compactMap(map[string]any{"module": input.GetModule(), "action": input.GetAction()})
	if assignments := stringListsToAny(input.GetAssignments()); len(assignments) > 0 {
		out["assignments"] = assignments
	}
	return out
}

func capabilitiesConfigToMap(cfg *contracts.CapabilitiesConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{"module": cfg.GetModule(), "provider": cfg.GetProvider()})
}

func capabilitiesInputToMap(input *contracts.CapabilitiesInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{"module": input.GetModule(), "provider": input.GetProvider()})
}

func subjectObjectActionConfigToMap(cfg *contracts.SubjectObjectActionConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{"module": cfg.GetModule(), "subject": cfg.GetSubject(), "object": cfg.GetObject(), "action": cfg.GetAction()})
}

func subjectObjectActionInputToMap(input *contracts.SubjectObjectActionInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{"module": input.GetModule(), "subject": input.GetSubject(), "object": input.GetObject(), "action": input.GetAction()})
}

func listConfigToMap(cfg *contracts.ListConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{"module": cfg.GetModule(), "filter": cfg.GetFilter(), "value": cfg.GetValue()})
}

func listInputToMap(input *contracts.ListInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{"module": input.GetModule(), "filter": input.GetFilter(), "value": input.GetValue()})
}

func relationConfigToMap(cfg *contracts.RelationConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{"module": cfg.GetModule(), "subject": cfg.GetSubject(), "relation": cfg.GetRelation(), "object": cfg.GetObject()})
}

func relationInputToMap(input *contracts.RelationInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{"module": input.GetModule(), "subject": input.GetSubject(), "relation": input.GetRelation(), "object": input.GetObject()})
}

func permitStepConfigToMap(cfg *contracts.PermitStepConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	out := structToMapProto(cfg.GetValues())
	if cfg.GetModule() != "" {
		out["module"] = cfg.GetModule()
	}
	return out
}

func permitStepInputToMap(input *contracts.PermitStepInput) map[string]any {
	if input == nil {
		return nil
	}
	out := structToMapProto(input.GetValues())
	if input.GetModule() != "" {
		out["module"] = input.GetModule()
	}
	return out
}

func authzCheckOutputFromMap(values map[string]any) *contracts.AuthzCheckOutput {
	return &contracts.AuthzCheckOutput{
		Subject:         stringValue(values["authz_subject"]),
		Object:          stringValue(values["authz_object"]),
		Action:          stringValue(values["authz_action"]),
		Allowed:         boolValue(values["authz_allowed"]),
		ResponseStatus:  int32(intValue(values["response_status"])),
		ResponseBody:    stringValue(values["response_body"]),
		ResponseHeaders: structFromAnyMap(anyMapValue(values["response_headers"])),
	}
}

func policyRuleOutputFromMap(values map[string]any, changedKey string) *contracts.PolicyRuleOutput {
	return &contracts.PolicyRuleOutput{
		Changed: boolValue(values[changedKey]),
		Rule:    stringSliceValue(firstNonNil(values["authz_rule"], values["rule"])),
	}
}

func roleAssignOutputFromMap(values map[string]any) *contracts.RoleAssignOutput {
	return &contracts.RoleAssignOutput{
		Action:      stringValue(values["authz_role_action"]),
		Assignments: stringListsFromAny(values["authz_role_assignments"]),
	}
}

func capabilitiesOutputFromMap(values map[string]any) *contracts.CapabilitiesOutput {
	return &contracts.CapabilitiesOutput{
		Module:              stringValue(values["module"]),
		Provider:            stringValue(values["provider"]),
		Capabilities:        stringSliceValue(values["capabilities"]),
		Descriptors:         contractCapabilityDescriptorsFromAny(values["capability_descriptors"]),
		Health:              stringValue(values["health"]),
		MissingRequirements: stringSliceValue(values["missing_requirements"]),
	}
}

func subjectObjectActionOutputFromMap(values map[string]any) *contracts.SubjectObjectActionOutput {
	return &contracts.SubjectObjectActionOutput{
		Allowed: boolValue(values["allowed"]),
		Changed: boolValue(firstNonNil(
			values["granted"],
			values["revoked"],
			values["policy_added"],
			values["added"],
			values["removed"],
		)),
		Subject: stringValue(values["subject"]),
		Object:  stringValue(values["object"]),
		Action:  stringValue(values["action"]),
	}
}

func relationOutputFromMap(values map[string]any) *contracts.RelationOutput {
	return &contracts.RelationOutput{
		Changed:  boolValue(firstNonNil(values["added"], values["removed"])),
		Subject:  stringValue(values["subject"]),
		Relation: stringValue(values["relation"]),
		Object:   stringValue(values["object"]),
	}
}

func genericOutputFromMap(values map[string]any) *contracts.GenericStepOutput {
	return &contracts.GenericStepOutput{Output: structFromAnyMap(values)}
}

func mergeStringFields(base, override map[string]any) map[string]any {
	out := copyMap(base)
	for k, v := range override {
		switch typed := v.(type) {
		case string:
			if typed != "" {
				out[k] = typed
			}
		case []any:
			if len(typed) > 0 {
				out[k] = typed
			}
		case map[string]any:
			if len(typed) > 0 {
				out[k] = typed
			}
		default:
			if v != nil {
				out[k] = v
			}
		}
	}
	return out
}

func compactMap(values map[string]any) map[string]any {
	out := make(map[string]any, len(values))
	for k, v := range values {
		switch typed := v.(type) {
		case string:
			if typed != "" {
				out[k] = typed
			}
		case nil:
		default:
			out[k] = v
		}
	}
	return out
}

func copyMap(values map[string]any) map[string]any {
	out := make(map[string]any, len(values))
	for k, v := range values {
		out[k] = v
	}
	return out
}

func stringsToAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func stringListsToAny(values []*contracts.StringList) []any {
	out := make([]any, 0, len(values))
	for _, row := range values {
		out = append(out, stringsToAny(row.GetValues()))
	}
	return out
}

func stringListsFromAny(value any) []*contracts.StringList {
	rows, ok := value.([][]string)
	if ok {
		out := make([]*contracts.StringList, 0, len(rows))
		for _, row := range rows {
			out = append(out, &contracts.StringList{Values: append([]string(nil), row...)})
		}
		return out
	}
	return nil
}

func extraFieldsToAny(values []*contracts.ExtraField) []any {
	out := make([]any, 0, len(values))
	for _, field := range values {
		if field.GetKey() == "" && field.GetValue() == "" {
			continue
		}
		out = append(out, compactMap(map[string]any{"key": field.GetKey(), "value": field.GetValue()}))
	}
	return out
}

func structToMapProto(value *structpb.Struct) map[string]any {
	if value == nil {
		return nil
	}
	return value.AsMap()
}

func structFromAnyMap(value any) *structpb.Struct {
	values, ok := value.(map[string]any)
	if !ok || len(values) == 0 {
		return nil
	}
	out, err := structpb.NewStruct(values)
	if err != nil {
		return nil
	}
	return out
}

func anyMapValue(value any) map[string]any {
	values, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return values
}

func firstNonNil(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func stringValue(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func boolValue(value any) bool {
	if b, ok := value.(bool); ok {
		return b
	}
	return false
}

func intValue(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func stringSliceValue(value any) []string {
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			out = append(out, fmt.Sprint(value))
		}
		return out
	default:
		return nil
	}
}

func contractCapabilityDescriptorsFromAny(value any) []*contracts.CapabilityDescriptor {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]*contracts.CapabilityDescriptor, 0, len(values))
	for _, value := range values {
		descriptor := capabilityDescriptorFromMap(anyMapValue(value))
		if descriptor != nil {
			out = append(out, descriptor)
		}
	}
	return out
}

func capabilityDescriptorFromMap(values map[string]any) *contracts.CapabilityDescriptor {
	if values == nil {
		return nil
	}
	return &contracts.CapabilityDescriptor{
		Mode:              contractAuthzMode(stringValue(values["mode"])),
		Operations:        contractAuthzOperations(stringSliceValue(values["operations"])),
		Configured:        boolValue(values["configured"]),
		Source:            stringValue(values["source"]),
		Health:            stringValue(values["health"]),
		UnsupportedReason: stringValue(values["unsupported_reason"]),
	}
}

func contractAuthzMode(mode string) contracts.AuthzMode {
	switch AuthzCapability(mode) {
	case CapabilityRBAC:
		return contracts.AuthzMode_AUTHZ_MODE_RBAC
	case CapabilityABAC:
		return contracts.AuthzMode_AUTHZ_MODE_ABAC
	case CapabilityReBAC:
		return contracts.AuthzMode_AUTHZ_MODE_REBAC
	case CapabilityACL:
		return contracts.AuthzMode_AUTHZ_MODE_ACL
	default:
		return contracts.AuthzMode_AUTHZ_MODE_UNSPECIFIED
	}
}

func contractAuthzOperations(operations []string) []contracts.AuthzOperation {
	out := make([]contracts.AuthzOperation, 0, len(operations))
	for _, operation := range operations {
		switch AuthzOperation(operation) {
		case OperationCheck:
			out = append(out, contracts.AuthzOperation_AUTHZ_OPERATION_CHECK)
		case OperationManageRoles:
			out = append(out, contracts.AuthzOperation_AUTHZ_OPERATION_MANAGE_ROLES)
		case OperationManagePolicies:
			out = append(out, contracts.AuthzOperation_AUTHZ_OPERATION_MANAGE_POLICIES)
		case OperationManageRelations:
			out = append(out, contracts.AuthzOperation_AUTHZ_OPERATION_MANAGE_RELATIONS)
		case OperationList:
			out = append(out, contracts.AuthzOperation_AUTHZ_OPERATION_LIST)
		}
	}
	return out
}
