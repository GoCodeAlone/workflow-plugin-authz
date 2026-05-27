package internal

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type scopeCatalogModule struct {
	name       string
	mu         sync.RWMutex
	scopes     map[string]*contracts.ScopeDeclaration
	resources  map[string]*contracts.ResourceDeclaration
	actions    map[string]*contracts.ActionDeclaration
	attributes map[string]*contracts.AttributeDeclaration
	relations  map[string]*contracts.RelationDeclaration
	uiActions  map[string]*contracts.UIActionDeclaration
}

func newScopeCatalogModule(name string, config map[string]any) *scopeCatalogModule {
	m := &scopeCatalogModule{
		name:       name,
		scopes:     map[string]*contracts.ScopeDeclaration{},
		resources:  map[string]*contracts.ResourceDeclaration{},
		actions:    map[string]*contracts.ActionDeclaration{},
		attributes: map[string]*contracts.AttributeDeclaration{},
		relations:  map[string]*contracts.RelationDeclaration{},
		uiActions:  map[string]*contracts.UIActionDeclaration{},
	}
	for _, scope := range scopeDeclarationsFromAny(config["scopes"], "", "") {
		m.upsert(scope)
	}
	if declarations := declarationSetFromAny(config["declarations"], "", ""); declarations != nil {
		_, _ = m.registerDeclarations(&contracts.RegisterDeclarationsInput{Declarations: declarations})
	}
	return m
}

func (m *scopeCatalogModule) Init() error { return nil }

func (m *scopeCatalogModule) Start(_ context.Context) error { return nil }

func (m *scopeCatalogModule) Stop(_ context.Context) error { return nil }

func (m *scopeCatalogModule) InvokeMethod(method string, input map[string]any) (map[string]any, error) {
	switch method {
	case "RegisterScopes":
		out, err := m.registerScopes(registerScopesInputFromMap(input))
		if err != nil {
			return nil, err
		}
		return registerScopesOutputToMap(out), nil
	case "ListScopes":
		return map[string]any{"scopes": scopeDeclarationsToMaps(m.listScopes(listScopesInputFromMap(input)))}, nil
	case "ResolveSubjectScopes":
		out := m.resolveSubjectScopes(resolveSubjectScopesInputFromMap(input))
		return resolveSubjectScopesOutputToMap(out), nil
	case "RegisterDeclarations":
		out, err := m.registerDeclarations(registerDeclarationsInputFromMap(input))
		if err != nil {
			return nil, err
		}
		return registerDeclarationsOutputToMap(out), nil
	case "ListDeclarations":
		return map[string]any{"declarations": declarationSetToMap(m.listDeclarations(listDeclarationsInputFromMap(input)))}, nil
	case "ResolveProjectionInputs":
		return map[string]any{"projection": projectionInputsToMap(m.resolveProjectionInputs(resolveProjectionInputsInputFromMap(input)))}, nil
	default:
		return nil, fmt.Errorf("authz scope catalog method %q is not supported", method)
	}
}

func (m *scopeCatalogModule) registerScopes(input *contracts.RegisterScopesInput) (*contracts.RegisterScopesOutput, error) {
	if input == nil {
		return &contracts.RegisterScopesOutput{}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	registered := int32(0)
	out := make([]*contracts.ScopeDeclaration, 0, len(input.GetScopes()))
	for _, incoming := range input.GetScopes() {
		scope := cloneScopeDeclaration(incoming)
		if scope.GetName() == "" {
			continue
		}
		if scope.OwnerPlugin == "" {
			scope.OwnerPlugin = input.GetOwnerPlugin()
		}
		if scope.OwnerModule == "" {
			scope.OwnerModule = input.GetOwnerModule()
		}
		if _, exists := m.scopes[scope.GetName()]; !exists {
			registered++
		}
		m.upsertLocked(scope)
		out = append(out, cloneScopeDeclaration(scope))
	}
	return &contracts.RegisterScopesOutput{Registered: registered, Scopes: out}, nil
}

func (m *scopeCatalogModule) listScopes(input *contracts.ListScopesInput) []*contracts.ScopeDeclaration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*contracts.ScopeDeclaration, 0, len(m.scopes))
	for _, scope := range m.scopes {
		if input != nil {
			if input.GetContext() != "" && scope.GetContext() != input.GetContext() {
				continue
			}
			if input.GetOwnerPlugin() != "" && scope.GetOwnerPlugin() != input.GetOwnerPlugin() {
				continue
			}
			if input.GetOwnerModule() != "" && scope.GetOwnerModule() != input.GetOwnerModule() {
				continue
			}
		}
		out = append(out, cloneScopeDeclaration(scope))
	}
	sortScopes(out)
	return out
}

func (m *scopeCatalogModule) resolveSubjectScopes(input *contracts.ResolveSubjectScopesInput) *contracts.ResolveSubjectScopesOutput {
	if input == nil {
		return &contracts.ResolveSubjectScopesOutput{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := map[string]struct{}{}
	for _, scope := range append(input.GetRoleScopes(), input.GetDirectScopes()...) {
		if scope != "" {
			names[scope] = struct{}{}
		}
	}
	resolved := make([]string, 0, len(names))
	declared := make([]*contracts.ScopeDeclaration, 0, len(names))
	for name := range names {
		scope, ok := m.scopes[name]
		if input.GetContext() != "" && ok && scope.GetContext() != input.GetContext() {
			continue
		}
		resolved = append(resolved, name)
		if ok {
			declared = append(declared, cloneScopeDeclaration(scope))
		}
	}
	sort.Strings(resolved)
	sortScopes(declared)
	return &contracts.ResolveSubjectScopesOutput{
		Subject:        input.GetSubject(),
		Scopes:         resolved,
		DeclaredScopes: declared,
	}
}

func (m *scopeCatalogModule) upsert(scope *contracts.ScopeDeclaration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertLocked(scope)
}

func (m *scopeCatalogModule) upsertLocked(scope *contracts.ScopeDeclaration) {
	if scope == nil || scope.GetName() == "" {
		return
	}
	m.scopes[scope.GetName()] = cloneScopeDeclaration(scope)
}

func scopeCatalogConfigToMap(cfg *contracts.ScopeCatalogConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	out := map[string]any{}
	if scopes := scopeDeclarationsToMaps(cfg.GetScopes()); len(scopes) > 0 {
		out["scopes"] = scopes
	}
	if cfg.GetAllowRuntimeRegistration() {
		out["allow_runtime_registration"] = true
	}
	if cfg.GetDeclarations() != nil {
		out["declarations"] = declarationSetToMap(cfg.GetDeclarations())
	}
	return out
}

func typedRegisterScopes(module *scopeCatalogModule) sdk.TypedStepHandler[*contracts.RegisterScopesInput, *contracts.RegisterScopesInput, *contracts.RegisterScopesOutput] {
	return func(_ context.Context, req sdk.TypedStepRequest[*contracts.RegisterScopesInput, *contracts.RegisterScopesInput]) (*sdk.TypedStepResult[*contracts.RegisterScopesOutput], error) {
		config := cloneRegisterScopesInput(req.Config)
		input := cloneRegisterScopesInput(req.Input)
		if input.GetOwnerPlugin() == "" {
			input.OwnerPlugin = config.GetOwnerPlugin()
		}
		if input.GetOwnerModule() == "" {
			input.OwnerModule = config.GetOwnerModule()
		}
		if len(input.GetScopes()) == 0 {
			input.Scopes = config.GetScopes()
		}
		out, err := module.registerScopes(input)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.RegisterScopesOutput]{Output: out}, nil
	}
}

func registerScopesInputFromMap(values map[string]any) *contracts.RegisterScopesInput {
	if values == nil {
		return nil
	}
	return &contracts.RegisterScopesInput{
		OwnerPlugin: stringValue(values["owner_plugin"]),
		OwnerModule: stringValue(values["owner_module"]),
		Scopes:      scopeDeclarationsFromAny(values["scopes"], stringValue(values["owner_plugin"]), stringValue(values["owner_module"])),
	}
}

func listScopesInputFromMap(values map[string]any) *contracts.ListScopesInput {
	if values == nil {
		return nil
	}
	return &contracts.ListScopesInput{
		Context:     stringValue(values["context"]),
		OwnerPlugin: stringValue(values["owner_plugin"]),
		OwnerModule: stringValue(values["owner_module"]),
	}
}

func resolveSubjectScopesInputFromMap(values map[string]any) *contracts.ResolveSubjectScopesInput {
	if values == nil {
		return nil
	}
	return &contracts.ResolveSubjectScopesInput{
		Subject:      stringValue(values["subject"]),
		DirectScopes: stringSliceValue(values["direct_scopes"]),
		RoleScopes:   stringSliceValue(values["role_scopes"]),
		Context:      stringValue(values["context"]),
	}
}

func registerScopesOutputToMap(out *contracts.RegisterScopesOutput) map[string]any {
	if out == nil {
		return map[string]any{"registered": 0, "scopes": []map[string]any{}}
	}
	return map[string]any{"registered": int(out.GetRegistered()), "scopes": scopeDeclarationsToMaps(out.GetScopes())}
}

func resolveSubjectScopesOutputToMap(out *contracts.ResolveSubjectScopesOutput) map[string]any {
	if out == nil {
		return map[string]any{"scopes": []string{}, "declared_scopes": []map[string]any{}}
	}
	return map[string]any{
		"subject":         out.GetSubject(),
		"scopes":          append([]string(nil), out.GetScopes()...),
		"declared_scopes": scopeDeclarationsToMaps(out.GetDeclaredScopes()),
	}
}

func scopeDeclarationsFromAny(value any, ownerPlugin, ownerModule string) []*contracts.ScopeDeclaration {
	switch scopes := value.(type) {
	case []*contracts.ScopeDeclaration:
		out := make([]*contracts.ScopeDeclaration, 0, len(scopes))
		for _, scope := range scopes {
			cloned := cloneScopeDeclaration(scope)
			if cloned.OwnerPlugin == "" {
				cloned.OwnerPlugin = ownerPlugin
			}
			if cloned.OwnerModule == "" {
				cloned.OwnerModule = ownerModule
			}
			out = append(out, cloned)
		}
		return out
	case []map[string]any:
		out := make([]*contracts.ScopeDeclaration, 0, len(scopes))
		for _, scope := range scopes {
			out = append(out, scopeDeclarationFromMap(scope, ownerPlugin, ownerModule))
		}
		return out
	case []any:
		out := make([]*contracts.ScopeDeclaration, 0, len(scopes))
		for _, scope := range scopes {
			if values := mapValue(scope); len(values) > 0 {
				out = append(out, scopeDeclarationFromMap(values, ownerPlugin, ownerModule))
			}
		}
		return out
	default:
		return nil
	}
}

func scopeDeclarationFromMap(values map[string]any, ownerPlugin, ownerModule string) *contracts.ScopeDeclaration {
	if values == nil {
		return nil
	}
	return &contracts.ScopeDeclaration{
		Name:        stringValue(values["name"]),
		Context:     stringValue(values["context"]),
		Resource:    stringValue(values["resource"]),
		Actions:     stringSliceValue(values["actions"]),
		Description: stringValue(values["description"]),
		OwnerPlugin: defaultString(stringValue(values["owner_plugin"]), ownerPlugin),
		OwnerModule: defaultString(stringValue(values["owner_module"]), ownerModule),
		Category:    stringValue(values["category"]),
	}
}

func mapValue(value any) map[string]any {
	switch v := value.(type) {
	case map[string]any:
		return v
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			if s, ok := key.(string); ok {
				out[s] = item
			}
		}
		return out
	default:
		return map[string]any{}
	}
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func scopeDeclarationsToMaps(scopes []*contracts.ScopeDeclaration) []map[string]any {
	out := make([]map[string]any, 0, len(scopes))
	for _, scope := range scopes {
		if scope == nil {
			continue
		}
		out = append(out, compactMap(map[string]any{
			"name":         scope.GetName(),
			"context":      scope.GetContext(),
			"resource":     scope.GetResource(),
			"actions":      stringsToAny(scope.GetActions()),
			"description":  scope.GetDescription(),
			"owner_plugin": scope.GetOwnerPlugin(),
			"owner_module": scope.GetOwnerModule(),
			"category":     scope.GetCategory(),
		}))
	}
	return out
}

func cloneScopeDeclaration(scope *contracts.ScopeDeclaration) *contracts.ScopeDeclaration {
	if scope == nil {
		return nil
	}
	return &contracts.ScopeDeclaration{
		Name:        scope.GetName(),
		Context:     scope.GetContext(),
		Resource:    scope.GetResource(),
		Actions:     append([]string(nil), scope.GetActions()...),
		Description: scope.GetDescription(),
		OwnerPlugin: scope.GetOwnerPlugin(),
		OwnerModule: scope.GetOwnerModule(),
		Category:    scope.GetCategory(),
	}
}

func cloneRegisterScopesInput(input *contracts.RegisterScopesInput) *contracts.RegisterScopesInput {
	if input == nil {
		return &contracts.RegisterScopesInput{}
	}
	return &contracts.RegisterScopesInput{
		OwnerPlugin: input.GetOwnerPlugin(),
		OwnerModule: input.GetOwnerModule(),
		Scopes:      scopeDeclarationsFromAny(input.GetScopes(), input.GetOwnerPlugin(), input.GetOwnerModule()),
	}
}

func sortScopes(scopes []*contracts.ScopeDeclaration) {
	sort.Slice(scopes, func(i, j int) bool {
		return scopes[i].GetName() < scopes[j].GetName()
	})
}
