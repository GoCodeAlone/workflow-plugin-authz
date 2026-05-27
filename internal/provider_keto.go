package internal

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
	keto "github.com/ory/keto-client-go/v25"
)

type ketoClient interface {
	CreateRelationship(context.Context, ketoTuple) error
	DeleteRelationship(context.Context, ketoTuple) error
	Check(context.Context, ketoTuple) (bool, error)
}

type ketoScopeProvider struct {
	name   string
	store  *scopeRoleStore
	client ketoClient
}

type ketoTuple struct {
	Namespace  string
	Object     string
	Relation   string
	SubjectID  string
	SubjectSet *ketoSubjectSet
}

type ketoSubjectSet struct {
	Namespace string
	Object    string
	Relation  string
}

func newKetoScopeProvider(name string, client ketoClient) *ketoScopeProvider {
	return &ketoScopeProvider{name: name, store: newScopeRoleStore("keto"), client: client}
}

func (p *ketoScopeProvider) Name() string { return p.name }

func (p *ketoScopeProvider) DeclareScopes(ctx context.Context, scopes []*contracts.ScopeDeclaration) error {
	return p.store.DeclareScopes(ctx, scopes)
}

func (p *ketoScopeProvider) UpsertRole(ctx context.Context, grant RoleScopeGrant) error {
	if err := p.store.UpsertRole(ctx, grant); err != nil {
		return err
	}
	for _, scope := range grant.Scopes {
		if err := p.client.CreateRelationship(ctx, ketoRoleScopeTuple(grant.Context, grant.Role, scope)); err != nil {
			return err
		}
	}
	return nil
}

func (p *ketoScopeProvider) AssignRole(ctx context.Context, assignment SubjectRoleAssignment) error {
	if err := p.store.AssignRole(ctx, assignment); err != nil {
		return err
	}
	if assignment.Role != "" {
		if err := p.client.CreateRelationship(ctx, ketoSubjectRoleTuple(assignment.Context, assignment.Role, assignment.Subject)); err != nil {
			return err
		}
	}
	for _, scope := range assignment.DirectScopes {
		if err := p.client.CreateRelationship(ctx, ketoDirectScopeTuple(assignment.Subject, scope)); err != nil {
			return err
		}
	}
	return nil
}

func (p *ketoScopeProvider) ListAssignments(ctx context.Context, filter AssignmentFilter) ([]SubjectRoleAssignment, error) {
	return p.store.ListAssignments(ctx, filter)
}

func (p *ketoScopeProvider) RemoveAssignment(ctx context.Context, assignment SubjectRoleAssignment) error {
	if err := p.store.RemoveAssignment(ctx, assignment); err != nil {
		return err
	}
	if assignment.Role != "" {
		return p.client.DeleteRelationship(ctx, ketoSubjectRoleTuple(assignment.Context, assignment.Role, assignment.Subject))
	}
	return nil
}

func (p *ketoScopeProvider) CheckScope(ctx context.Context, check ScopeCheck) (ScopeCheckResult, error) {
	scopeName := normalizeCheckScope(check)
	result := ScopeCheckResult{
		Provider: p.store.provider,
		Subject:  strings.TrimSpace(check.Subject),
		Context:  strings.TrimSpace(check.Context),
		Scope:    scopeName,
	}
	local, err := p.store.CheckScope(ctx, check)
	if err != nil {
		return result, err
	}
	if !local.Allowed {
		local.Provider = p.store.provider
		return local, nil
	}
	allowed, err := p.client.Check(ctx, ketoDirectScopeTuple(result.Subject, scopeName))
	if err != nil {
		return result, err
	}
	result.Allowed = allowed
	result.MatchedRole = local.MatchedRole
	result.MatchedScopes = local.MatchedScopes
	if !allowed {
		result.Reason = "keto denied"
	}
	return result, nil
}

func ketoRoleObject(contextName, role string) string {
	return contextName + ":" + role
}

func ketoRoleScopeTuple(contextName, role, scope string) ketoTuple {
	return ketoTuple{
		Namespace: "scope",
		Object:    scope,
		Relation:  "granted",
		SubjectSet: &ketoSubjectSet{
			Namespace: "role",
			Object:    ketoRoleObject(contextName, role),
			Relation:  "member",
		},
	}
}

func ketoSubjectRoleTuple(contextName, role, subject string) ketoTuple {
	return ketoTuple{
		Namespace: "role",
		Object:    ketoRoleObject(contextName, role),
		Relation:  "member",
		SubjectID: subject,
	}
}

func ketoDirectScopeTuple(subject, scope string) ketoTuple {
	return ketoTuple{
		Namespace: "scope",
		Object:    scope,
		Relation:  "granted",
		SubjectID: subject,
	}
}

func (t ketoTuple) equal(other ketoTuple) bool {
	if t.Namespace != other.Namespace || t.Object != other.Object || t.Relation != other.Relation || t.SubjectID != other.SubjectID {
		return false
	}
	if t.SubjectSet == nil || other.SubjectSet == nil {
		return t.SubjectSet == nil && other.SubjectSet == nil
	}
	return *t.SubjectSet == *other.SubjectSet
}

type ketoSDKClient struct {
	relationships keto.RelationshipAPI
	permissions   keto.PermissionAPI
}

func newKetoSDKClient(readURL, writeURL string) *ketoSDKClient {
	readCfg := keto.NewConfiguration()
	readCfg.Servers = keto.ServerConfigurations{{URL: defaultString(readURL, "http://localhost:4466")}}
	readCfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	writeCfg := keto.NewConfiguration()
	writeCfg.Servers = keto.ServerConfigurations{{URL: defaultString(writeURL, defaultString(readURL, "http://localhost:4467"))}}
	writeCfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	return &ketoSDKClient{
		permissions:   keto.NewAPIClient(readCfg).PermissionAPI,
		relationships: keto.NewAPIClient(writeCfg).RelationshipAPI,
	}
}

func (c *ketoSDKClient) CreateRelationship(ctx context.Context, tuple ketoTuple) error {
	body := keto.NewCreateRelationshipBody()
	body.SetNamespace(tuple.Namespace)
	body.SetObject(tuple.Object)
	body.SetRelation(tuple.Relation)
	if tuple.SubjectSet != nil {
		body.SetSubjectSet(*keto.NewSubjectSet(tuple.SubjectSet.Namespace, tuple.SubjectSet.Object, tuple.SubjectSet.Relation))
	} else {
		body.SetSubjectId(tuple.SubjectID)
	}
	_, _, err := c.relationships.CreateRelationship(ctx).CreateRelationshipBody(*body).Execute()
	return ignoreKetoConflict(err)
}

func (c *ketoSDKClient) DeleteRelationship(ctx context.Context, tuple ketoTuple) error {
	req := c.relationships.DeleteRelationships(ctx).Namespace(tuple.Namespace).Object(tuple.Object).Relation(tuple.Relation)
	if tuple.SubjectSet != nil {
		req = req.SubjectSetNamespace(tuple.SubjectSet.Namespace).SubjectSetObject(tuple.SubjectSet.Object).SubjectSetRelation(tuple.SubjectSet.Relation)
	} else {
		req = req.SubjectId(tuple.SubjectID)
	}
	_, err := req.Execute()
	return ignoreKetoConflict(err)
}

func (c *ketoSDKClient) Check(ctx context.Context, tuple ketoTuple) (bool, error) {
	req := c.permissions.CheckPermission(ctx).Namespace(tuple.Namespace).Object(tuple.Object).Relation(tuple.Relation).SubjectId(tuple.SubjectID).MaxDepth(32)
	result, _, err := req.Execute()
	if err != nil {
		return false, err
	}
	if result == nil {
		return false, nil
	}
	return result.GetAllowed(), nil
}

func ignoreKetoConflict(err error) error {
	if err == nil {
		return nil
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "409") || strings.Contains(text, "already") {
		return nil
	}
	return fmt.Errorf("keto sdk: %w", err)
}

var _ ScopeRoleProvider = (*ketoScopeProvider)(nil)
