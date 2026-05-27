package internal

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
	permitapi "github.com/permitio/permit-golang/pkg/api"
	permitconfig "github.com/permitio/permit-golang/pkg/config"
	"github.com/permitio/permit-golang/pkg/enforcement"
	permitmodels "github.com/permitio/permit-golang/pkg/models"
	"github.com/permitio/permit-golang/pkg/permit"
)

type permitScopeClient interface {
	DeclareResource(ctx context.Context, resource string, actions []string) error
	UpsertRole(ctx context.Context, role string, permissions []string) error
	AssignRole(ctx context.Context, subject, role, tenant string) error
	UnassignRole(ctx context.Context, subject, role, tenant string) error
	Check(ctx context.Context, subject, action, resource string) (bool, error)
}

type permitScopeProvider struct {
	name   string
	tenant string
	store  *scopeRoleStore
	client permitScopeClient
}

func newPermitScopeProvider(name string, client permitScopeClient) *permitScopeProvider {
	return &permitScopeProvider{
		name:   name,
		tenant: "default",
		store:  newScopeRoleStore("permit"),
		client: client,
	}
}

func (p *permitScopeProvider) Name() string { return p.name }

func (p *permitScopeProvider) DeclareScopes(ctx context.Context, scopes []*contracts.ScopeDeclaration) error {
	if err := p.store.DeclareScopes(ctx, scopes); err != nil {
		return err
	}
	grouped := map[string]map[string]struct{}{}
	for _, scope := range scopes {
		cloned := cloneScopeDeclaration(scope)
		normalizeScopeDeclaration(cloned)
		if cloned == nil || cloned.GetResource() == "" {
			continue
		}
		if grouped[cloned.GetResource()] == nil {
			grouped[cloned.GetResource()] = map[string]struct{}{}
		}
		for _, action := range cloned.GetActions() {
			grouped[cloned.GetResource()][action] = struct{}{}
		}
	}
	for resource, actionSet := range grouped {
		actions := make([]string, 0, len(actionSet))
		for action := range actionSet {
			actions = append(actions, action)
		}
		if err := p.client.DeclareResource(ctx, resource, actions); err != nil {
			return err
		}
	}
	return nil
}

func (p *permitScopeProvider) UpsertRole(ctx context.Context, grant RoleScopeGrant) error {
	if err := p.store.UpsertRole(ctx, grant); err != nil {
		return err
	}
	permissions := make([]string, 0, len(grant.Scopes))
	for _, scopeName := range grant.Scopes {
		scope := scopeDeclarationFromName(scopeName)
		permissions = append(permissions, permitPermission(scope.GetResource(), firstScopeAction(scope)))
	}
	return p.client.UpsertRole(ctx, permitRoleKey(grant.Context, grant.Role), permissions)
}

func (p *permitScopeProvider) AssignRole(ctx context.Context, assignment SubjectRoleAssignment) error {
	if err := p.store.AssignRole(ctx, assignment); err != nil {
		return err
	}
	if assignment.Role != "" {
		if err := p.client.AssignRole(ctx, assignment.Subject, permitRoleKey(assignment.Context, assignment.Role), p.tenant); err != nil {
			return err
		}
	}
	if len(assignment.DirectScopes) > 0 {
		directRole := permitDirectRoleKey(assignment.Context, assignment.Subject)
		direct := RoleScopeGrant{Role: directRole, Context: assignment.Context, Scopes: assignment.DirectScopes}
		permissions := make([]string, 0, len(direct.Scopes))
		for _, scopeName := range direct.Scopes {
			scope := scopeDeclarationFromName(scopeName)
			permissions = append(permissions, permitPermission(scope.GetResource(), firstScopeAction(scope)))
		}
		if err := p.client.UpsertRole(ctx, directRole, permissions); err != nil {
			return err
		}
		if err := p.client.AssignRole(ctx, assignment.Subject, directRole, p.tenant); err != nil {
			return err
		}
	}
	return nil
}

func (p *permitScopeProvider) ListAssignments(ctx context.Context, filter AssignmentFilter) ([]SubjectRoleAssignment, error) {
	return p.store.ListAssignments(ctx, filter)
}

func (p *permitScopeProvider) RemoveAssignment(ctx context.Context, assignment SubjectRoleAssignment) error {
	if err := p.store.RemoveAssignment(ctx, assignment); err != nil {
		return err
	}
	if assignment.Role != "" {
		return p.client.UnassignRole(ctx, assignment.Subject, permitRoleKey(assignment.Context, assignment.Role), p.tenant)
	}
	return nil
}

func (p *permitScopeProvider) CheckScope(ctx context.Context, check ScopeCheck) (ScopeCheckResult, error) {
	scopeName := normalizeCheckScope(check)
	scope := scopeDeclarationFromName(scopeName)
	result := ScopeCheckResult{
		Provider: p.store.provider,
		Subject:  strings.TrimSpace(check.Subject),
		Context:  strings.TrimSpace(check.Context),
		Scope:    scopeName,
	}
	if result.Subject == "" || result.Context == "" || result.Scope == "" {
		result.Reason = "subject, context, and scope are required"
		return result, nil
	}
	local, err := p.store.CheckScope(ctx, check)
	if err != nil {
		return result, err
	}
	if !local.Allowed {
		local.Provider = p.store.provider
		return local, nil
	}
	allowed, err := p.client.Check(ctx, result.Subject, firstScopeAction(scope), scope.GetResource())
	if err != nil {
		return result, err
	}
	result.Allowed = allowed
	result.MatchedRole = local.MatchedRole
	result.MatchedScopes = local.MatchedScopes
	if !allowed {
		result.Reason = "permit denied"
	}
	return result, nil
}

type permitSDKScopeClient struct {
	client *permit.Client
	tenant string
}

func newPermitSDKScopeClient(cfg permitModuleConfig) *permitSDKScopeClient {
	context := permitconfig.NewPermitContext(permitconfig.ProjectAPIKeyLevel, cfg.Project, cfg.Environment)
	permitCfg := permitconfig.NewPermitConfig(cfg.APIURL, cfg.APIKey, cfg.PDPURL, false, context, nil).Build()
	return &permitSDKScopeClient{
		client: permit.New(permitCfg),
		tenant: "default",
	}
}

func (c *permitSDKScopeClient) DeclareResource(ctx context.Context, resource string, actions []string) error {
	actionBlocks := make(map[string]permitmodels.ActionBlockEditable, len(actions))
	for _, action := range actions {
		block := permitmodels.NewActionBlockEditable()
		block.SetName(action)
		actionBlocks[action] = *block
	}
	_, err := c.client.Api.Resources.Get(ctx, resource)
	if err == nil {
		return nil
	}
	_, err = c.client.Api.Resources.Create(ctx, *permitmodels.NewResourceCreate(resource, resource, actionBlocks))
	return ignorePermitConflict(err)
}

func (c *permitSDKScopeClient) UpsertRole(ctx context.Context, role string, permissions []string) error {
	if _, err := c.client.Api.Roles.Get(ctx, role); err != nil {
		if _, createErr := c.client.Api.Roles.Create(ctx, *permitmodels.NewRoleCreate(role, role)); createErr != nil {
			if err := ignorePermitConflict(createErr); err != nil {
				return err
			}
		}
	}
	return ignorePermitConflict(c.client.Api.Roles.AssignPermissions(ctx, role, permissions))
}

func (c *permitSDKScopeClient) AssignRole(ctx context.Context, subject, role, tenant string) error {
	if _, err := c.client.SyncUser(ctx, *permitmodels.NewUserCreate(subject)); err != nil {
		return err
	}
	_, err := c.client.Api.Users.AssignRole(ctx, subject, role, defaultString(tenant, c.tenant))
	return ignorePermitConflict(err)
}

func (c *permitSDKScopeClient) UnassignRole(ctx context.Context, subject, role, tenant string) error {
	_, err := c.client.Api.Users.UnassignRole(ctx, subject, role, defaultString(tenant, c.tenant))
	return ignorePermitConflict(err)
}

func (c *permitSDKScopeClient) Check(ctx context.Context, subject, action, resource string) (bool, error) {
	_ = ctx
	user := enforcement.UserBuilder(subject).Build()
	res := enforcement.ResourceBuilder(resource).WithKey(resource).WithTenant(c.tenant).Build()
	return c.client.Check(user, enforcement.Action(action), res)
}

func permitPermission(resource, action string) string {
	return resource + ":" + action
}

func permitRoleKey(contextName, role string) string {
	return sanitizePermitKey(contextName) + "__" + sanitizePermitKey(role)
}

func permitDirectRoleKey(contextName, subject string) string {
	return "direct__" + sanitizePermitKey(contextName) + "__" + sanitizePermitKey(subject)
}

func sanitizePermitKey(value string) string {
	value = strings.TrimSpace(value)
	value = strings.NewReplacer("@", "_at_", ".", "_", ":", "_", "/", "_", " ", "_").Replace(value)
	if value == "" {
		return "default"
	}
	return value
}

func firstScopeAction(scope *contracts.ScopeDeclaration) string {
	if len(scope.GetActions()) == 0 {
		return ""
	}
	return scope.GetActions()[0]
}

func ignorePermitConflict(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "409") || strings.Contains(strings.ToLower(err.Error()), "already") {
		return nil
	}
	var target interface{ Error() string }
	if errors.As(err, &target) && strings.Contains(strings.ToLower(target.Error()), "conflict") {
		return nil
	}
	return fmt.Errorf("permit sdk: %w", err)
}

var _ ScopeRoleProvider = (*permitScopeProvider)(nil)
var _ = permitapi.DefaultPerPageLimit
