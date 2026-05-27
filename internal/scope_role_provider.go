package internal

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

type ScopeRoleProvider interface {
	Name() string
	DeclareScopes(context.Context, []*contracts.ScopeDeclaration) error
	UpsertRole(context.Context, RoleScopeGrant) error
	AssignRole(context.Context, SubjectRoleAssignment) error
	ListAssignments(context.Context, AssignmentFilter) ([]SubjectRoleAssignment, error)
	RemoveAssignment(context.Context, SubjectRoleAssignment) error
	CheckScope(context.Context, ScopeCheck) (ScopeCheckResult, error)
}

type RoleScopeGrant struct {
	Role    string
	Context string
	Scopes  []string
}

type SubjectRoleAssignment struct {
	Subject      string
	Role         string
	Context      string
	DirectScopes []string
}

type AssignmentFilter struct {
	Subject string
	Role    string
	Context string
}

type ScopeCheck struct {
	Subject  string
	Context  string
	Scope    string
	Resource string
	Action   string
}

type ScopeCheckResult struct {
	Allowed       bool
	Provider      string
	Subject       string
	Context       string
	Scope         string
	MatchedRole   string
	MatchedScopes []string
	Reason        string
}

type scopeRoleStore struct {
	provider string
	mu       sync.RWMutex
	scopes   map[string]*contracts.ScopeDeclaration
	roles    map[string]RoleScopeGrant
	assigns  []SubjectRoleAssignment
}

func newScopeRoleStore(provider string) *scopeRoleStore {
	return &scopeRoleStore{
		provider: provider,
		scopes:   map[string]*contracts.ScopeDeclaration{},
		roles:    map[string]RoleScopeGrant{},
	}
}

func (s *scopeRoleStore) DeclareScopes(_ context.Context, scopes []*contracts.ScopeDeclaration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, incoming := range scopes {
		scope := cloneScopeDeclaration(incoming)
		if scope == nil || strings.TrimSpace(scope.GetName()) == "" {
			continue
		}
		normalizeScopeDeclaration(scope)
		if scope.GetContext() == "" || scope.GetResource() == "" || len(scope.GetActions()) == 0 {
			return fmt.Errorf("scope %q must declare context, resource, and at least one action", scope.GetName())
		}
		s.scopes[scope.GetName()] = scope
	}
	return nil
}

func (s *scopeRoleStore) UpsertRole(_ context.Context, grant RoleScopeGrant) error {
	grant.Role = strings.TrimSpace(grant.Role)
	grant.Context = strings.TrimSpace(grant.Context)
	if grant.Role == "" {
		return fmt.Errorf("role is required")
	}
	if grant.Context == "" {
		return fmt.Errorf("context is required")
	}
	scopes := uniqueStrings(grant.Scopes)
	s.mu.RLock()
	err := s.validateScopesLocked(grant.Context, scopes)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	grant.Scopes = scopes

	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[roleKey(grant.Context, grant.Role)] = cloneRoleScopeGrant(grant)
	return nil
}

func (s *scopeRoleStore) AssignRole(_ context.Context, assignment SubjectRoleAssignment) error {
	assignment.Subject = strings.TrimSpace(assignment.Subject)
	assignment.Role = strings.TrimSpace(assignment.Role)
	assignment.Context = strings.TrimSpace(assignment.Context)
	if assignment.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	if assignment.Context == "" {
		return fmt.Errorf("context is required")
	}
	assignment.DirectScopes = uniqueStrings(assignment.DirectScopes)

	s.mu.RLock()
	if err := s.validateScopesLocked(assignment.Context, assignment.DirectScopes); err != nil {
		s.mu.RUnlock()
		return err
	}
	if assignment.Role != "" {
		if _, ok := s.roles[roleKey(assignment.Context, assignment.Role)]; !ok && len(assignment.DirectScopes) == 0 {
			s.mu.RUnlock()
			return fmt.Errorf("role %q is not defined in context %q", assignment.Role, assignment.Context)
		}
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.assigns {
		if sameAssignmentIdentity(existing, assignment) {
			s.assigns[i] = cloneSubjectRoleAssignment(assignment)
			return nil
		}
	}
	s.assigns = append(s.assigns, cloneSubjectRoleAssignment(assignment))
	return nil
}

func (s *scopeRoleStore) ListAssignments(_ context.Context, filter AssignmentFilter) ([]SubjectRoleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SubjectRoleAssignment, 0, len(s.assigns))
	for _, assignment := range s.assigns {
		if filter.Subject != "" && assignment.Subject != filter.Subject {
			continue
		}
		if filter.Role != "" && assignment.Role != filter.Role {
			continue
		}
		if filter.Context != "" && assignment.Context != filter.Context {
			continue
		}
		out = append(out, cloneSubjectRoleAssignment(assignment))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		if out[i].Context != out[j].Context {
			return out[i].Context < out[j].Context
		}
		return out[i].Role < out[j].Role
	})
	return out, nil
}

func (s *scopeRoleStore) RemoveAssignment(_ context.Context, target SubjectRoleAssignment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.assigns[:0]
	for _, assignment := range s.assigns {
		if sameAssignmentIdentity(assignment, target) {
			continue
		}
		kept = append(kept, assignment)
	}
	s.assigns = kept
	return nil
}

func (s *scopeRoleStore) CheckScope(_ context.Context, check ScopeCheck) (ScopeCheckResult, error) {
	scopeName := normalizeCheckScope(check)
	result := ScopeCheckResult{
		Provider: s.provider,
		Subject:  strings.TrimSpace(check.Subject),
		Context:  strings.TrimSpace(check.Context),
		Scope:    scopeName,
	}
	if result.Subject == "" {
		result.Reason = "subject is required"
		return result, nil
	}
	if result.Context == "" {
		result.Reason = "context is required"
		return result, nil
	}
	if result.Scope == "" {
		result.Reason = "scope is required"
		return result, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	declared, ok := s.scopes[result.Scope]
	if !ok {
		result.Reason = "scope is not declared"
		return result, nil
	}
	if declared.GetContext() != result.Context {
		result.Reason = "scope context mismatch"
		return result, nil
	}
	for _, assignment := range s.assigns {
		if assignment.Subject != result.Subject || assignment.Context != result.Context {
			continue
		}
		if containsString(assignment.DirectScopes, result.Scope) {
			result.Allowed = true
			result.MatchedRole = assignment.Role
			result.MatchedScopes = []string{result.Scope}
			return result, nil
		}
		grant, ok := s.roles[roleKey(assignment.Context, assignment.Role)]
		if !ok {
			continue
		}
		if containsString(grant.Scopes, result.Scope) {
			result.Allowed = true
			result.MatchedRole = grant.Role
			result.MatchedScopes = []string{result.Scope}
			return result, nil
		}
	}
	result.Reason = "no matching role or direct scope grant"
	return result, nil
}

func (s *scopeRoleStore) validateScopesLocked(contextName string, scopes []string) error {
	for _, name := range scopes {
		scope, ok := s.scopes[name]
		if !ok {
			return fmt.Errorf("scope %q is not declared", name)
		}
		if scope.GetContext() != contextName {
			return fmt.Errorf("scope %q belongs to context %q, not %q", name, scope.GetContext(), contextName)
		}
	}
	return nil
}

func roleKey(contextName, role string) string {
	return contextName + "\x00" + role
}

func normalizeScopeDeclaration(scope *contracts.ScopeDeclaration) {
	if scope == nil {
		return
	}
	scope.Name = strings.TrimSpace(scope.GetName())
	if scope.GetContext() == "" || scope.GetResource() == "" || len(scope.GetActions()) == 0 {
		parsed := scopeDeclarationFromName(scope.GetName())
		if scope.GetContext() == "" {
			scope.Context = parsed.GetContext()
		}
		if scope.GetResource() == "" {
			scope.Resource = parsed.GetResource()
		}
		if len(scope.GetActions()) == 0 {
			scope.Actions = parsed.GetActions()
		}
	}
	scope.Actions = uniqueStrings(scope.GetActions())
}

func scopeDeclarationFromName(name string) *contracts.ScopeDeclaration {
	parts := strings.Split(strings.TrimSpace(name), ":")
	scope := &contracts.ScopeDeclaration{Name: strings.TrimSpace(name)}
	if len(parts) >= 3 {
		scope.Context = parts[0]
		scope.Resource = strings.Join(parts[1:len(parts)-1], ".")
		scope.Actions = []string{parts[len(parts)-1]}
	}
	return scope
}

func normalizeCheckScope(check ScopeCheck) string {
	if strings.TrimSpace(check.Scope) != "" {
		return strings.TrimSpace(check.Scope)
	}
	if check.Context == "" || check.Resource == "" || check.Action == "" {
		return ""
	}
	return strings.TrimSpace(check.Context) + ":" + strings.TrimSpace(check.Resource) + ":" + strings.TrimSpace(check.Action)
}

func cloneRoleScopeGrant(grant RoleScopeGrant) RoleScopeGrant {
	return RoleScopeGrant{
		Role:    grant.Role,
		Context: grant.Context,
		Scopes:  append([]string(nil), grant.Scopes...),
	}
}

func cloneSubjectRoleAssignment(assignment SubjectRoleAssignment) SubjectRoleAssignment {
	return SubjectRoleAssignment{
		Subject:      assignment.Subject,
		Role:         assignment.Role,
		Context:      assignment.Context,
		DirectScopes: append([]string(nil), assignment.DirectScopes...),
	}
}

func sameAssignmentIdentity(a, b SubjectRoleAssignment) bool {
	return a.Subject == b.Subject && a.Role == b.Role && a.Context == b.Context
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func roleScopeGrantFromMap(values map[string]any) RoleScopeGrant {
	return RoleScopeGrant{
		Role:    stringValue(values["role"]),
		Context: stringValue(values["context"]),
		Scopes:  stringSliceValue(values["scopes"]),
	}
}

func roleScopeGrantToMap(grant RoleScopeGrant) map[string]any {
	return compactMap(map[string]any{
		"role":    grant.Role,
		"context": grant.Context,
		"scopes":  stringsToAny(grant.Scopes),
	})
}

func subjectRoleAssignmentFromMap(values map[string]any) SubjectRoleAssignment {
	return SubjectRoleAssignment{
		Subject:      stringValue(firstNonNil(values["subject"], values["user"])),
		Role:         stringValue(values["role"]),
		Context:      stringValue(values["context"]),
		DirectScopes: stringSliceValue(firstNonNil(values["direct_scopes"], values["scopes"])),
	}
}

func subjectRoleAssignmentToMap(assignment SubjectRoleAssignment) map[string]any {
	return compactMap(map[string]any{
		"subject":       assignment.Subject,
		"user":          assignment.Subject,
		"role":          assignment.Role,
		"context":       assignment.Context,
		"direct_scopes": stringsToAny(assignment.DirectScopes),
		"scopes":        stringsToAny(assignment.DirectScopes),
	})
}

func subjectRoleAssignmentsToMaps(assignments []SubjectRoleAssignment) []map[string]any {
	out := make([]map[string]any, 0, len(assignments))
	for _, assignment := range assignments {
		out = append(out, subjectRoleAssignmentToMap(assignment))
	}
	return out
}

func assignmentFilterFromMap(values map[string]any) AssignmentFilter {
	return AssignmentFilter{
		Subject: stringValue(firstNonNil(values["subject"], values["user"])),
		Role:    stringValue(values["role"]),
		Context: stringValue(values["context"]),
	}
}

func scopeCheckFromMap(values map[string]any) ScopeCheck {
	return ScopeCheck{
		Subject:  stringValue(firstNonNil(values["subject"], values["user"])),
		Context:  stringValue(values["context"]),
		Scope:    stringValue(values["scope"]),
		Resource: stringValue(values["resource"]),
		Action:   stringValue(values["action"]),
	}
}

func scopeCheckResultToMap(result ScopeCheckResult) map[string]any {
	return compactMap(map[string]any{
		"allowed":        result.Allowed,
		"provider":       result.Provider,
		"subject":        result.Subject,
		"context":        result.Context,
		"scope":          result.Scope,
		"matched_role":   result.MatchedRole,
		"matched_scopes": stringsToAny(result.MatchedScopes),
		"reason":         result.Reason,
	})
}
