package internal

import (
	"context"
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

type KetoModule struct {
	name     string
	config   ketoModuleConfig
	provider *ketoScopeProvider
}

type ketoModuleConfig struct {
	ReadURL  string `yaml:"readUrl"`
	WriteURL string `yaml:"writeUrl"`
}

func newKetoModule(name string, config map[string]any) (*KetoModule, error) {
	return &KetoModule{name: name, config: ketoModuleConfig{
		ReadURL:  stringValue(firstNonNil(config["readUrl"], config["read_url"])),
		WriteURL: stringValue(firstNonNil(config["writeUrl"], config["write_url"])),
	}}, nil
}

func (m *KetoModule) Init() error {
	m.provider = newKetoScopeProvider(m.name, newKetoSDKClient(m.config.ReadURL, m.config.WriteURL))
	return nil
}

func (m *KetoModule) Start(_ context.Context) error { return nil }

func (m *KetoModule) Stop(_ context.Context) error { return nil }

func (m *KetoModule) Name() string { return m.name }

func (m *KetoModule) DeclareScopes(ctx context.Context, scopes []*contracts.ScopeDeclaration) error {
	return m.provider.DeclareScopes(ctx, scopes)
}

func (m *KetoModule) UpsertRole(ctx context.Context, grant RoleScopeGrant) error {
	return m.provider.UpsertRole(ctx, grant)
}

func (m *KetoModule) AssignRole(ctx context.Context, assignment SubjectRoleAssignment) error {
	return m.provider.AssignRole(ctx, assignment)
}

func (m *KetoModule) ListAssignments(ctx context.Context, filter AssignmentFilter) ([]SubjectRoleAssignment, error) {
	return m.provider.ListAssignments(ctx, filter)
}

func (m *KetoModule) RemoveAssignment(ctx context.Context, assignment SubjectRoleAssignment) error {
	return m.provider.RemoveAssignment(ctx, assignment)
}

func (m *KetoModule) CheckScope(ctx context.Context, check ScopeCheck) (ScopeCheckResult, error) {
	return m.provider.CheckScope(ctx, check)
}

func (m *KetoModule) UpsertRelationTuple(ctx context.Context, tuple RelationTuple) error {
	return m.provider.UpsertRelationTuple(ctx, tuple)
}

func (m *KetoModule) RemoveRelationTuple(ctx context.Context, tuple RelationTuple) error {
	return m.provider.RemoveRelationTuple(ctx, tuple)
}

func (m *KetoModule) ListRelationTuples(ctx context.Context, filter RelationTupleFilter) ([]RelationTuple, error) {
	return m.provider.ListRelationTuples(ctx, filter)
}

func (m *KetoModule) CheckRelation(ctx context.Context, check RelationCheck) (RelationCheckResult, error) {
	return m.provider.CheckRelation(ctx, check)
}

func (m *KetoModule) InvokeMethod(method string, input map[string]any) (map[string]any, error) {
	switch method {
	case "GetCapabilities":
		return providerCapabilitiesInvoke(m.name, "keto", m, input, false)
	case "RequireCapabilities":
		return providerCapabilitiesInvoke(m.name, "keto", m, input, true)
	case "UpsertRelationTuple":
		return upsertRelationTupleInvoke(context.Background(), m, input)
	case "ListRelationTuples":
		return listRelationTuplesInvoke(context.Background(), m, input)
	case "RemoveRelationTuple":
		return removeRelationTupleInvoke(context.Background(), m, input)
	case "CheckRelation":
		return checkRelationInvoke(context.Background(), m, input)
	default:
		return nil, fmt.Errorf("authz keto method %q is not supported", method)
	}
}

func ketoModuleConfigToMap(cfg *contracts.KetoModuleConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{
		"readUrl":  cfg.GetReadUrl(),
		"writeUrl": cfg.GetWriteUrl(),
	})
}
