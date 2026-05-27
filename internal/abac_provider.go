package internal

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

var errUnsupportedABAC = errors.New("abac provider is not supported by this module configuration")

type AttributePolicyProvider interface {
	Name() string
	DeclareAttributes(context.Context, []*contracts.AttributeDeclaration) error
	UpsertAttributePolicy(context.Context, AttributePolicy) error
	ListAttributePolicies(context.Context, AttributePolicyFilter) ([]AttributePolicy, error)
	RemoveAttributePolicy(context.Context, AttributePolicyFilter) error
	CheckAttributes(context.Context, AttributeCheck) (AttributeCheckResult, error)
}

type AttributeCondition struct {
	Target    string
	Attribute string
	Operator  string
	Values    []string
}

type AttributePolicy struct {
	ID          string
	Context     string
	Resource    string
	Action      string
	Effect      string
	Conditions  []AttributeCondition
	Description string
	OwnerPlugin string
	OwnerModule string
}

type AttributePolicyFilter struct {
	ID          string
	Context     string
	Resource    string
	Action      string
	OwnerPlugin string
	OwnerModule string
}

type AttributeCheck struct {
	Subject               string
	Context               string
	Resource              string
	Action                string
	SubjectAttributes     map[string]string
	ResourceAttributes    map[string]string
	EnvironmentAttributes map[string]string
}

type AttributeCheckResult struct {
	Allowed         bool
	Subject         string
	Context         string
	Resource        string
	Action          string
	MatchedPolicyID string
	Reason          string
}

type attributePolicyStore struct {
	mu         sync.RWMutex
	attrs      map[string]*contracts.AttributeDeclaration
	policies   map[string]AttributePolicy
	provider   string
	supported  func() bool
	attributes []*contracts.AttributeDeclaration
}

func newAttributePolicyStore(provider string, supported func() bool) *attributePolicyStore {
	return &attributePolicyStore{
		attrs:     map[string]*contracts.AttributeDeclaration{},
		policies:  map[string]AttributePolicy{},
		provider:  provider,
		supported: supported,
	}
}

func (s *attributePolicyStore) DeclareAttributes(_ context.Context, attrs []*contracts.AttributeDeclaration) error {
	if err := s.ensureSupported(); err != nil {
		return err
	}
	set := &contracts.AuthzDeclarationSet{Attributes: cloneAttributeDeclarations(attrs)}
	if err := validateDeclarationSet(set); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, attr := range set.GetAttributes() {
		s.attrs[attributeDeclarationKey(attr.GetContext(), attr.GetTarget(), attr.GetName())] = cloneAttributeDeclaration(attr)
	}
	return nil
}

func (s *attributePolicyStore) UpsertAttributePolicy(_ context.Context, policy AttributePolicy) error {
	if err := s.ensureSupported(); err != nil {
		return err
	}
	policy = normalizeAttributePolicy(policy)
	if err := validateAttributePolicy(policy); err != nil {
		return err
	}
	s.mu.RLock()
	for _, condition := range policy.Conditions {
		if _, ok := s.attrs[attributeDeclarationKey(policy.Context, condition.Target, condition.Attribute)]; !ok {
			s.mu.RUnlock()
			return fmt.Errorf("attribute %q for target %q is not declared in context %q", condition.Attribute, condition.Target, policy.Context)
		}
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[attributePolicyKey(policy.Context, policy.ID)] = cloneAttributePolicy(policy)
	return nil
}

func (s *attributePolicyStore) ListAttributePolicies(_ context.Context, filter AttributePolicyFilter) ([]AttributePolicy, error) {
	if err := s.ensureSupported(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AttributePolicy, 0, len(s.policies))
	for _, policy := range s.policies {
		if !attributePolicyMatches(policy, filter) {
			continue
		}
		out = append(out, cloneAttributePolicy(policy))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *attributePolicyStore) RemoveAttributePolicy(_ context.Context, filter AttributePolicyFilter) error {
	if err := s.ensureSupported(); err != nil {
		return err
	}
	if strings.TrimSpace(filter.ID) == "" || strings.TrimSpace(filter.Context) == "" {
		return fmt.Errorf("id and context are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, attributePolicyKey(filter.Context, filter.ID))
	return nil
}

func (s *attributePolicyStore) CheckAttributes(_ context.Context, check AttributeCheck) (AttributeCheckResult, error) {
	result := AttributeCheckResult{
		Subject:  strings.TrimSpace(check.Subject),
		Context:  strings.TrimSpace(check.Context),
		Resource: strings.TrimSpace(check.Resource),
		Action:   strings.TrimSpace(check.Action),
	}
	if err := s.ensureSupported(); err != nil {
		return result, err
	}
	if result.Subject == "" || result.Context == "" || result.Resource == "" || result.Action == "" {
		result.Reason = "subject, context, resource, and action are required"
		return result, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, policy := range s.policies {
		if policy.Context != result.Context || policy.Resource != result.Resource || policy.Action != result.Action {
			continue
		}
		if attributeConditionsMatch(policy.Conditions, check) {
			result.MatchedPolicyID = policy.ID
			result.Allowed = strings.EqualFold(policy.Effect, "allow")
			if !result.Allowed {
				result.Reason = "matched non-allow policy"
			}
			return result, nil
		}
	}
	result.Reason = "no matching attribute policy"
	return result, nil
}

func (s *attributePolicyStore) ensureSupported() error {
	if s.supported != nil && !s.supported() {
		return errUnsupportedABAC
	}
	return nil
}

func attributeConditionsMatch(conditions []AttributeCondition, check AttributeCheck) bool {
	for _, condition := range conditions {
		actual, ok := attributeCheckBag(condition.Target, check)[condition.Attribute]
		if !ok || !attributeConditionMatches(condition, actual) {
			return false
		}
	}
	return true
}

func attributeCheckBag(target string, check AttributeCheck) map[string]string {
	switch strings.ToLower(target) {
	case "subject":
		return check.SubjectAttributes
	case "resource":
		return check.ResourceAttributes
	case "environment":
		return check.EnvironmentAttributes
	default:
		return nil
	}
}

func attributeConditionMatches(condition AttributeCondition, actual string) bool {
	switch strings.ToLower(defaultString(condition.Operator, "equals")) {
	case "equals":
		return len(condition.Values) > 0 && actual == condition.Values[0]
	case "in":
		return containsString(condition.Values, actual)
	default:
		return false
	}
}

func normalizeAttributePolicy(policy AttributePolicy) AttributePolicy {
	policy.ID = strings.TrimSpace(policy.ID)
	policy.Context = strings.TrimSpace(policy.Context)
	policy.Resource = strings.TrimSpace(policy.Resource)
	policy.Action = strings.TrimSpace(policy.Action)
	policy.Effect = defaultString(strings.TrimSpace(policy.Effect), "allow")
	for i := range policy.Conditions {
		policy.Conditions[i].Target = strings.TrimSpace(policy.Conditions[i].Target)
		policy.Conditions[i].Attribute = strings.TrimSpace(policy.Conditions[i].Attribute)
		policy.Conditions[i].Operator = defaultString(strings.TrimSpace(policy.Conditions[i].Operator), "equals")
		policy.Conditions[i].Values = uniqueStrings(policy.Conditions[i].Values)
	}
	return policy
}

func validateAttributePolicy(policy AttributePolicy) error {
	if policy.ID == "" || policy.Context == "" || policy.Resource == "" || policy.Action == "" {
		return fmt.Errorf("attribute policy requires id, context, resource, and action")
	}
	if !strings.EqualFold(policy.Effect, "allow") && !strings.EqualFold(policy.Effect, "deny") {
		return fmt.Errorf("attribute policy %q has unsupported effect %q", policy.ID, policy.Effect)
	}
	if len(policy.Conditions) == 0 {
		return fmt.Errorf("attribute policy %q requires at least one condition", policy.ID)
	}
	for _, condition := range policy.Conditions {
		if condition.Target == "" || condition.Attribute == "" || len(condition.Values) == 0 {
			return fmt.Errorf("attribute policy %q has an incomplete condition", policy.ID)
		}
		switch strings.ToLower(condition.Target) {
		case "subject", "resource", "environment":
		default:
			return fmt.Errorf("attribute policy %q has unsupported condition target %q", policy.ID, condition.Target)
		}
		switch strings.ToLower(condition.Operator) {
		case "equals", "in":
		default:
			return fmt.Errorf("attribute policy %q has unsupported condition operator %q", policy.ID, condition.Operator)
		}
	}
	return nil
}

func attributePolicyMatches(policy AttributePolicy, filter AttributePolicyFilter) bool {
	return (filter.ID == "" || policy.ID == filter.ID) &&
		(filter.Context == "" || policy.Context == filter.Context) &&
		(filter.Resource == "" || policy.Resource == filter.Resource) &&
		(filter.Action == "" || policy.Action == filter.Action) &&
		(filter.OwnerPlugin == "" || policy.OwnerPlugin == filter.OwnerPlugin) &&
		(filter.OwnerModule == "" || policy.OwnerModule == filter.OwnerModule)
}

func cloneAttributePolicy(policy AttributePolicy) AttributePolicy {
	policy.Conditions = cloneAttributeConditions(policy.Conditions)
	return policy
}

func cloneAttributeConditions(conditions []AttributeCondition) []AttributeCondition {
	out := make([]AttributeCondition, len(conditions))
	for i, condition := range conditions {
		out[i] = condition
		out[i].Values = append([]string(nil), condition.Values...)
	}
	return out
}

func attributeDeclarationKey(contextName, target, name string) string {
	return contextName + "/" + target + "/" + name
}

func attributePolicyKey(contextName, id string) string {
	return contextName + "/" + id
}

func declareAttributesInvoke(ctx context.Context, provider AttributePolicyProvider, input map[string]any) (map[string]any, error) {
	attrs := attributeDeclarationsFromAny(input["attributes"], stringValue(input["owner_plugin"]), stringValue(input["owner_module"]))
	if err := provider.DeclareAttributes(ctx, attrs); err != nil {
		return nil, err
	}
	return map[string]any{"registered": len(attrs), "attributes": attributeDeclarationsToMaps(attrs)}, nil
}

func upsertAttributePolicyInvoke(ctx context.Context, provider AttributePolicyProvider, input map[string]any) (map[string]any, error) {
	policy := attributePolicyFromMap(mapValue(input["policy"]))
	if err := provider.UpsertAttributePolicy(ctx, policy); err != nil {
		return nil, err
	}
	return map[string]any{"changed": true, "policy": attributePolicyToMap(policy)}, nil
}

func listAttributePoliciesInvoke(ctx context.Context, provider AttributePolicyProvider, input map[string]any) (map[string]any, error) {
	policies, err := provider.ListAttributePolicies(ctx, attributePolicyFilterFromMap(mapValue(input["filter"])))
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(policies))
	for _, policy := range policies {
		items = append(items, attributePolicyToMap(policy))
	}
	return map[string]any{"policies": items}, nil
}

func removeAttributePolicyInvoke(ctx context.Context, provider AttributePolicyProvider, input map[string]any) (map[string]any, error) {
	if err := provider.RemoveAttributePolicy(ctx, attributePolicyFilterFromMap(mapValue(input["filter"]))); err != nil {
		return nil, err
	}
	return map[string]any{"changed": true}, nil
}

func checkAttributesInvoke(ctx context.Context, provider AttributePolicyProvider, input map[string]any) (map[string]any, error) {
	result, err := provider.CheckAttributes(ctx, attributeCheckFromMap(input))
	if err != nil {
		return attributeCheckResultToMap(result), err
	}
	return attributeCheckResultToMap(result), nil
}

func attributePolicyFromMap(values map[string]any) AttributePolicy {
	return AttributePolicy{
		ID:          stringValue(values["id"]),
		Context:     stringValue(values["context"]),
		Resource:    stringValue(values["resource"]),
		Action:      stringValue(values["action"]),
		Effect:      stringValue(values["effect"]),
		Conditions:  attributeConditionsFromAny(values["conditions"]),
		Description: stringValue(values["description"]),
		OwnerPlugin: stringValue(values["owner_plugin"]),
		OwnerModule: stringValue(values["owner_module"]),
	}
}

func attributePolicyFilterFromMap(values map[string]any) AttributePolicyFilter {
	return AttributePolicyFilter{
		ID:          stringValue(values["id"]),
		Context:     stringValue(values["context"]),
		Resource:    stringValue(values["resource"]),
		Action:      stringValue(values["action"]),
		OwnerPlugin: stringValue(values["owner_plugin"]),
		OwnerModule: stringValue(values["owner_module"]),
	}
}

func attributeConditionsFromAny(value any) []AttributeCondition {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]AttributeCondition, 0, len(items))
	for _, item := range items {
		values := mapValue(item)
		out = append(out, AttributeCondition{
			Target:    stringValue(values["target"]),
			Attribute: stringValue(values["attribute"]),
			Operator:  stringValue(values["operator"]),
			Values:    stringSliceValue(values["values"]),
		})
	}
	return out
}

func attributeCheckFromMap(values map[string]any) AttributeCheck {
	return AttributeCheck{
		Subject:               stringValue(values["subject"]),
		Context:               stringValue(values["context"]),
		Resource:              stringValue(values["resource"]),
		Action:                stringValue(values["action"]),
		SubjectAttributes:     stringMapFromAny(values["subject_attributes"]),
		ResourceAttributes:    stringMapFromAny(values["resource_attributes"]),
		EnvironmentAttributes: stringMapFromAny(values["environment_attributes"]),
	}
}

func attributePolicyToMap(policy AttributePolicy) map[string]any {
	return compactMap(map[string]any{
		"id":           policy.ID,
		"context":      policy.Context,
		"resource":     policy.Resource,
		"action":       policy.Action,
		"effect":       policy.Effect,
		"conditions":   attributeConditionsToMaps(policy.Conditions),
		"description":  policy.Description,
		"owner_plugin": policy.OwnerPlugin,
		"owner_module": policy.OwnerModule,
	})
}

func attributeConditionsToMaps(conditions []AttributeCondition) []map[string]any {
	out := make([]map[string]any, 0, len(conditions))
	for _, condition := range conditions {
		out = append(out, compactMap(map[string]any{
			"target":    condition.Target,
			"attribute": condition.Attribute,
			"operator":  condition.Operator,
			"values":    stringsToAny(condition.Values),
		}))
	}
	return out
}

func attributeCheckResultToMap(result AttributeCheckResult) map[string]any {
	return compactMap(map[string]any{
		"allowed":           result.Allowed,
		"subject":           result.Subject,
		"context":           result.Context,
		"resource":          result.Resource,
		"action":            result.Action,
		"matched_policy_id": result.MatchedPolicyID,
		"reason":            result.Reason,
	})
}

func stringMapFromAny(value any) map[string]string {
	values := mapValue(value)
	out := make(map[string]string, len(values))
	for key, item := range values {
		out[key] = fmt.Sprint(item)
	}
	return out
}
