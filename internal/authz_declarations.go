package internal

import (
	"fmt"
	"sort"
	"strings"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
)

var allowedAttributeDataTypes = map[string]bool{
	"string":      true,
	"number":      true,
	"int":         true,
	"float":       true,
	"bool":        true,
	"boolean":     true,
	"string_list": true,
}

func (m *scopeCatalogModule) registerDeclarations(input *contracts.RegisterDeclarationsInput) (*contracts.RegisterDeclarationsOutput, error) {
	if input == nil || input.GetDeclarations() == nil {
		return &contracts.RegisterDeclarationsOutput{Declarations: &contracts.AuthzDeclarationSet{}}, nil
	}
	set := cloneDeclarationSet(input.GetDeclarations())
	ownerPlugin := defaultString(input.GetOwnerPlugin(), set.GetOwnerPlugin())
	ownerModule := defaultString(input.GetOwnerModule(), set.GetOwnerModule())
	applyDeclarationOwners(set, ownerPlugin, ownerModule)
	if err := validateDeclarationSet(set); err != nil {
		return nil, err
	}

	registered := int32(0)
	if len(set.GetScopes()) > 0 {
		scopeOut, err := m.registerScopes(&contracts.RegisterScopesInput{
			Scopes:      set.GetScopes(),
			OwnerPlugin: ownerPlugin,
			OwnerModule: ownerModule,
		})
		if err != nil {
			return nil, err
		}
		registered += scopeOut.GetRegistered()
		set.Scopes = scopeOut.GetScopes()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, resource := range set.GetResources() {
		key := resourceKey(resource.GetContext(), resource.GetName())
		if _, exists := m.resources[key]; !exists {
			registered++
		}
		m.resources[key] = cloneResourceDeclaration(resource)
	}
	for _, action := range set.GetActions() {
		key := actionKey(action.GetContext(), action.GetResource(), action.GetName())
		if _, exists := m.actions[key]; !exists {
			registered++
		}
		m.actions[key] = cloneActionDeclaration(action)
	}
	for _, attribute := range set.GetAttributes() {
		key := attributeKey(attribute.GetContext(), attribute.GetName())
		if _, exists := m.attributes[key]; !exists {
			registered++
		}
		m.attributes[key] = cloneAttributeDeclaration(attribute)
	}
	for _, relation := range set.GetRelations() {
		key := relationKey(relation.GetContext(), relation.GetObjectType(), relation.GetName())
		if _, exists := m.relations[key]; !exists {
			registered++
		}
		m.relations[key] = cloneRelationDeclaration(relation)
	}
	for _, action := range set.GetUiActions() {
		key := uiActionKey(action.GetContext(), action.GetId())
		if _, exists := m.uiActions[key]; !exists {
			registered++
		}
		m.uiActions[key] = cloneUIActionDeclaration(action)
	}
	return &contracts.RegisterDeclarationsOutput{Registered: registered, Declarations: set}, nil
}

func (m *scopeCatalogModule) listDeclarations(input *contracts.ListDeclarationsInput) *contracts.AuthzDeclarationSet {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := &contracts.AuthzDeclarationSet{}
	scopeInput := &contracts.ListScopesInput{}
	if input != nil {
		scopeInput.Context = input.GetContext()
		scopeInput.OwnerPlugin = input.GetOwnerPlugin()
		scopeInput.OwnerModule = input.GetOwnerModule()
	}
	out.Scopes = m.listScopes(scopeInput)
	for _, resource := range m.resources {
		if declarationMatches(input, resource.GetContext(), resource.GetOwnerPlugin(), resource.GetOwnerModule()) {
			out.Resources = append(out.Resources, cloneResourceDeclaration(resource))
		}
	}
	for _, action := range m.actions {
		if declarationMatches(input, action.GetContext(), action.GetOwnerPlugin(), action.GetOwnerModule()) {
			out.Actions = append(out.Actions, cloneActionDeclaration(action))
		}
	}
	for _, attribute := range m.attributes {
		if declarationMatches(input, attribute.GetContext(), attribute.GetOwnerPlugin(), attribute.GetOwnerModule()) {
			out.Attributes = append(out.Attributes, cloneAttributeDeclaration(attribute))
		}
	}
	for _, relation := range m.relations {
		if declarationMatches(input, relation.GetContext(), relation.GetOwnerPlugin(), relation.GetOwnerModule()) {
			out.Relations = append(out.Relations, cloneRelationDeclaration(relation))
		}
	}
	for _, action := range m.uiActions {
		if declarationMatches(input, action.GetContext(), action.GetOwnerPlugin(), action.GetOwnerModule()) {
			out.UiActions = append(out.UiActions, cloneUIActionDeclaration(action))
		}
	}
	sortDeclarationSet(out)
	return out
}

func (m *scopeCatalogModule) resolveProjectionInputs(input *contracts.ResolveProjectionInputsInput) *contracts.ProjectionInputs {
	set := m.listDeclarations(&contracts.ListDeclarationsInput{
		Context:     input.GetContext(),
		OwnerPlugin: input.GetOwnerPlugin(),
		OwnerModule: input.GetOwnerModule(),
	})
	projection := &contracts.ProjectionInputs{}
	lookupIDs := map[string]bool{}
	for _, scope := range set.GetScopes() {
		projection.ScopeNames = append(projection.ScopeNames, scope.GetName())
	}
	for _, resource := range set.GetResources() {
		projection.ResourceNames = append(projection.ResourceNames, resource.GetName())
		if resource.GetLookupSourceId() != "" {
			lookupIDs[resource.GetLookupSourceId()] = true
		}
	}
	for _, action := range set.GetActions() {
		projection.ActionNames = append(projection.ActionNames, action.GetResource()+":"+action.GetName())
	}
	for _, attribute := range set.GetAttributes() {
		projection.AttributeNames = append(projection.AttributeNames, attribute.GetName())
		if attribute.GetLookupSourceId() != "" {
			lookupIDs[attribute.GetLookupSourceId()] = true
		}
	}
	for _, relation := range set.GetRelations() {
		projection.RelationNames = append(projection.RelationNames, relation.GetObjectType()+":"+relation.GetName())
	}
	for _, action := range set.GetUiActions() {
		projection.UiActionIds = append(projection.UiActionIds, action.GetId())
	}
	for id := range lookupIDs {
		projection.LookupSourceIds = append(projection.LookupSourceIds, id)
	}
	sort.Strings(projection.ScopeNames)
	sort.Strings(projection.ResourceNames)
	sort.Strings(projection.ActionNames)
	sort.Strings(projection.AttributeNames)
	sort.Strings(projection.RelationNames)
	sort.Strings(projection.UiActionIds)
	sort.Strings(projection.LookupSourceIds)
	return projection
}

func validateDeclarationSet(set *contracts.AuthzDeclarationSet) error {
	for _, resource := range set.GetResources() {
		if resource.GetName() == "" || resource.GetContext() == "" {
			return fmt.Errorf("resource declarations require name and context")
		}
	}
	for _, action := range set.GetActions() {
		if action.GetName() == "" || action.GetContext() == "" || action.GetResource() == "" {
			return fmt.Errorf("action declarations require name, context, and resource")
		}
	}
	for _, attribute := range set.GetAttributes() {
		if attribute.GetName() == "" || attribute.GetContext() == "" || attribute.GetTarget() == "" {
			return fmt.Errorf("attribute declarations require name, context, and target")
		}
		dataType := strings.ToLower(attribute.GetDataType())
		if !allowedAttributeDataTypes[dataType] {
			return fmt.Errorf("attribute %q has unsupported data_type %q", attribute.GetName(), attribute.GetDataType())
		}
		attribute.DataType = dataType
	}
	for _, relation := range set.GetRelations() {
		if relation.GetName() == "" || relation.GetContext() == "" || relation.GetSubjectType() == "" || relation.GetObjectType() == "" {
			return fmt.Errorf("relation declarations require name, context, subject_type, and object_type")
		}
	}
	for _, action := range set.GetUiActions() {
		if action.GetId() == "" || action.GetContext() == "" || action.GetLabel() == "" {
			return fmt.Errorf("ui action declarations require id, context, and label")
		}
	}
	return nil
}

func registerDeclarationsInputFromMap(values map[string]any) *contracts.RegisterDeclarationsInput {
	return &contracts.RegisterDeclarationsInput{
		OwnerPlugin:  stringValue(values["owner_plugin"]),
		OwnerModule:  stringValue(values["owner_module"]),
		Declarations: declarationSetFromAny(values["declarations"], stringValue(values["owner_plugin"]), stringValue(values["owner_module"])),
	}
}

func listDeclarationsInputFromMap(values map[string]any) *contracts.ListDeclarationsInput {
	return &contracts.ListDeclarationsInput{
		Context:     stringValue(values["context"]),
		OwnerPlugin: stringValue(values["owner_plugin"]),
		OwnerModule: stringValue(values["owner_module"]),
	}
}

func resolveProjectionInputsInputFromMap(values map[string]any) *contracts.ResolveProjectionInputsInput {
	return &contracts.ResolveProjectionInputsInput{
		Context:     stringValue(values["context"]),
		OwnerPlugin: stringValue(values["owner_plugin"]),
		OwnerModule: stringValue(values["owner_module"]),
	}
}

func registerDeclarationsOutputToMap(out *contracts.RegisterDeclarationsOutput) map[string]any {
	if out == nil {
		return map[string]any{"registered": 0, "declarations": declarationSetToMap(nil)}
	}
	return map[string]any{"registered": int(out.GetRegistered()), "declarations": declarationSetToMap(out.GetDeclarations())}
}

func declarationSetFromAny(value any, ownerPlugin, ownerModule string) *contracts.AuthzDeclarationSet {
	switch v := value.(type) {
	case *contracts.AuthzDeclarationSet:
		out := cloneDeclarationSet(v)
		applyDeclarationOwners(out, defaultString(ownerPlugin, out.GetOwnerPlugin()), defaultString(ownerModule, out.GetOwnerModule()))
		return out
	case map[string]any:
		out := &contracts.AuthzDeclarationSet{
			OwnerPlugin: stringValue(firstNonNil(v["owner_plugin"], ownerPlugin)),
			OwnerModule: stringValue(firstNonNil(v["owner_module"], ownerModule)),
		}
		out.Scopes = scopeDeclarationsFromAny(v["scopes"], out.GetOwnerPlugin(), out.GetOwnerModule())
		out.Resources = resourceDeclarationsFromAny(v["resources"], out.GetOwnerPlugin(), out.GetOwnerModule())
		out.Actions = actionDeclarationsFromAny(v["actions"], out.GetOwnerPlugin(), out.GetOwnerModule())
		out.Attributes = attributeDeclarationsFromAny(v["attributes"], out.GetOwnerPlugin(), out.GetOwnerModule())
		out.Relations = relationDeclarationsFromAny(v["relations"], out.GetOwnerPlugin(), out.GetOwnerModule())
		out.UiActions = uiActionDeclarationsFromAny(v["ui_actions"], out.GetOwnerPlugin(), out.GetOwnerModule())
		return out
	default:
		return nil
	}
}

func declarationSetToMap(set *contracts.AuthzDeclarationSet) map[string]any {
	if set == nil {
		set = &contracts.AuthzDeclarationSet{}
	}
	return compactMap(map[string]any{
		"owner_plugin": set.GetOwnerPlugin(),
		"owner_module": set.GetOwnerModule(),
		"scopes":       scopeDeclarationsToMaps(set.GetScopes()),
		"resources":    resourceDeclarationsToMaps(set.GetResources()),
		"actions":      actionDeclarationsToMaps(set.GetActions()),
		"attributes":   attributeDeclarationsToMaps(set.GetAttributes()),
		"relations":    relationDeclarationsToMaps(set.GetRelations()),
		"ui_actions":   uiActionDeclarationsToMaps(set.GetUiActions()),
	})
}

func projectionInputsToMap(projection *contracts.ProjectionInputs) map[string]any {
	if projection == nil {
		projection = &contracts.ProjectionInputs{}
	}
	return map[string]any{
		"scope_names":       append([]string(nil), projection.GetScopeNames()...),
		"resource_names":    append([]string(nil), projection.GetResourceNames()...),
		"action_names":      append([]string(nil), projection.GetActionNames()...),
		"attribute_names":   append([]string(nil), projection.GetAttributeNames()...),
		"relation_names":    append([]string(nil), projection.GetRelationNames()...),
		"ui_action_ids":     append([]string(nil), projection.GetUiActionIds()...),
		"lookup_source_ids": append([]string(nil), projection.GetLookupSourceIds()...),
	}
}

func applyDeclarationOwners(set *contracts.AuthzDeclarationSet, ownerPlugin, ownerModule string) {
	if set == nil {
		return
	}
	if set.OwnerPlugin == "" {
		set.OwnerPlugin = ownerPlugin
	}
	if set.OwnerModule == "" {
		set.OwnerModule = ownerModule
	}
	for _, scope := range set.GetScopes() {
		if scope.OwnerPlugin == "" {
			scope.OwnerPlugin = set.GetOwnerPlugin()
		}
		if scope.OwnerModule == "" {
			scope.OwnerModule = set.GetOwnerModule()
		}
	}
	for _, resource := range set.GetResources() {
		if resource.OwnerPlugin == "" {
			resource.OwnerPlugin = set.GetOwnerPlugin()
		}
		if resource.OwnerModule == "" {
			resource.OwnerModule = set.GetOwnerModule()
		}
	}
	for _, action := range set.GetActions() {
		if action.OwnerPlugin == "" {
			action.OwnerPlugin = set.GetOwnerPlugin()
		}
		if action.OwnerModule == "" {
			action.OwnerModule = set.GetOwnerModule()
		}
	}
	for _, attribute := range set.GetAttributes() {
		if attribute.OwnerPlugin == "" {
			attribute.OwnerPlugin = set.GetOwnerPlugin()
		}
		if attribute.OwnerModule == "" {
			attribute.OwnerModule = set.GetOwnerModule()
		}
	}
	for _, relation := range set.GetRelations() {
		if relation.OwnerPlugin == "" {
			relation.OwnerPlugin = set.GetOwnerPlugin()
		}
		if relation.OwnerModule == "" {
			relation.OwnerModule = set.GetOwnerModule()
		}
	}
	for _, action := range set.GetUiActions() {
		if action.OwnerPlugin == "" {
			action.OwnerPlugin = set.GetOwnerPlugin()
		}
		if action.OwnerModule == "" {
			action.OwnerModule = set.GetOwnerModule()
		}
	}
}

func declarationMatches(input *contracts.ListDeclarationsInput, contextName, ownerPlugin, ownerModule string) bool {
	if input == nil {
		return true
	}
	if input.GetContext() != "" && contextName != input.GetContext() {
		return false
	}
	if input.GetOwnerPlugin() != "" && ownerPlugin != input.GetOwnerPlugin() {
		return false
	}
	if input.GetOwnerModule() != "" && ownerModule != input.GetOwnerModule() {
		return false
	}
	return true
}

func resourceDeclarationsFromAny(value any, ownerPlugin, ownerModule string) []*contracts.ResourceDeclaration {
	switch items := value.(type) {
	case []*contracts.ResourceDeclaration:
		out := cloneResourceDeclarations(items)
		for _, item := range out {
			if item.OwnerPlugin == "" {
				item.OwnerPlugin = ownerPlugin
			}
			if item.OwnerModule == "" {
				item.OwnerModule = ownerModule
			}
		}
		return out
	case []map[string]any:
		anyItems := make([]any, len(items))
		for i, item := range items {
			anyItems[i] = item
		}
		return resourceDeclarationsFromAny(anyItems, ownerPlugin, ownerModule)
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]*contracts.ResourceDeclaration, 0, len(items))
	for _, item := range items {
		v := mapValue(item)
		out = append(out, &contracts.ResourceDeclaration{
			Name:           stringValue(v["name"]),
			Context:        stringValue(v["context"]),
			DisplayName:    stringValue(v["display_name"]),
			Description:    stringValue(v["description"]),
			OwnerPlugin:    defaultString(stringValue(v["owner_plugin"]), ownerPlugin),
			OwnerModule:    defaultString(stringValue(v["owner_module"]), ownerModule),
			Category:       stringValue(v["category"]),
			LookupSourceId: stringValue(v["lookup_source_id"]),
		})
	}
	return out
}

func actionDeclarationsFromAny(value any, ownerPlugin, ownerModule string) []*contracts.ActionDeclaration {
	switch items := value.(type) {
	case []*contracts.ActionDeclaration:
		out := cloneActionDeclarations(items)
		for _, item := range out {
			if item.OwnerPlugin == "" {
				item.OwnerPlugin = ownerPlugin
			}
			if item.OwnerModule == "" {
				item.OwnerModule = ownerModule
			}
		}
		return out
	case []map[string]any:
		anyItems := make([]any, len(items))
		for i, item := range items {
			anyItems[i] = item
		}
		return actionDeclarationsFromAny(anyItems, ownerPlugin, ownerModule)
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]*contracts.ActionDeclaration, 0, len(items))
	for _, item := range items {
		v := mapValue(item)
		out = append(out, &contracts.ActionDeclaration{
			Name:        stringValue(v["name"]),
			Context:     stringValue(v["context"]),
			Resource:    stringValue(v["resource"]),
			Description: stringValue(v["description"]),
			OwnerPlugin: defaultString(stringValue(v["owner_plugin"]), ownerPlugin),
			OwnerModule: defaultString(stringValue(v["owner_module"]), ownerModule),
			Category:    stringValue(v["category"]),
		})
	}
	return out
}

func attributeDeclarationsFromAny(value any, ownerPlugin, ownerModule string) []*contracts.AttributeDeclaration {
	switch items := value.(type) {
	case []*contracts.AttributeDeclaration:
		out := cloneAttributeDeclarations(items)
		for _, item := range out {
			if item.OwnerPlugin == "" {
				item.OwnerPlugin = ownerPlugin
			}
			if item.OwnerModule == "" {
				item.OwnerModule = ownerModule
			}
		}
		return out
	case []map[string]any:
		anyItems := make([]any, len(items))
		for i, item := range items {
			anyItems[i] = item
		}
		return attributeDeclarationsFromAny(anyItems, ownerPlugin, ownerModule)
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]*contracts.AttributeDeclaration, 0, len(items))
	for _, item := range items {
		v := mapValue(item)
		out = append(out, &contracts.AttributeDeclaration{
			Name:           stringValue(v["name"]),
			Context:        stringValue(v["context"]),
			Target:         stringValue(v["target"]),
			DataType:       stringValue(v["data_type"]),
			AllowedValues:  attributeValuesFromAny(v["allowed_values"]),
			LookupSourceId: stringValue(v["lookup_source_id"]),
			Description:    stringValue(v["description"]),
			OwnerPlugin:    defaultString(stringValue(v["owner_plugin"]), ownerPlugin),
			OwnerModule:    defaultString(stringValue(v["owner_module"]), ownerModule),
			Category:       stringValue(v["category"]),
		})
	}
	return out
}

func relationDeclarationsFromAny(value any, ownerPlugin, ownerModule string) []*contracts.RelationDeclaration {
	switch items := value.(type) {
	case []*contracts.RelationDeclaration:
		out := cloneRelationDeclarations(items)
		for _, item := range out {
			if item.OwnerPlugin == "" {
				item.OwnerPlugin = ownerPlugin
			}
			if item.OwnerModule == "" {
				item.OwnerModule = ownerModule
			}
		}
		return out
	case []map[string]any:
		anyItems := make([]any, len(items))
		for i, item := range items {
			anyItems[i] = item
		}
		return relationDeclarationsFromAny(anyItems, ownerPlugin, ownerModule)
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]*contracts.RelationDeclaration, 0, len(items))
	for _, item := range items {
		v := mapValue(item)
		out = append(out, &contracts.RelationDeclaration{
			Name:        stringValue(v["name"]),
			Context:     stringValue(v["context"]),
			SubjectType: stringValue(v["subject_type"]),
			ObjectType:  stringValue(v["object_type"]),
			Description: stringValue(v["description"]),
			OwnerPlugin: defaultString(stringValue(v["owner_plugin"]), ownerPlugin),
			OwnerModule: defaultString(stringValue(v["owner_module"]), ownerModule),
			Category:    stringValue(v["category"]),
		})
	}
	return out
}

func uiActionDeclarationsFromAny(value any, ownerPlugin, ownerModule string) []*contracts.UIActionDeclaration {
	switch items := value.(type) {
	case []*contracts.UIActionDeclaration:
		out := cloneUIActionDeclarations(items)
		for _, item := range out {
			if item.OwnerPlugin == "" {
				item.OwnerPlugin = ownerPlugin
			}
			if item.OwnerModule == "" {
				item.OwnerModule = ownerModule
			}
		}
		return out
	case []map[string]any:
		anyItems := make([]any, len(items))
		for i, item := range items {
			anyItems[i] = item
		}
		return uiActionDeclarationsFromAny(anyItems, ownerPlugin, ownerModule)
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]*contracts.UIActionDeclaration, 0, len(items))
	for _, item := range items {
		v := mapValue(item)
		out = append(out, &contracts.UIActionDeclaration{
			Id:             stringValue(v["id"]),
			Context:        stringValue(v["context"]),
			Label:          stringValue(v["label"]),
			Route:          stringValue(v["route"]),
			RequiredScopes: stringSliceValue(v["required_scopes"]),
			Description:    stringValue(v["description"]),
			OwnerPlugin:    defaultString(stringValue(v["owner_plugin"]), ownerPlugin),
			OwnerModule:    defaultString(stringValue(v["owner_module"]), ownerModule),
			Category:       stringValue(v["category"]),
		})
	}
	return out
}

func attributeValuesFromAny(value any) []*contracts.AttributeValue {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]*contracts.AttributeValue, 0, len(items))
	for _, item := range items {
		v := mapValue(item)
		out = append(out, &contracts.AttributeValue{Value: stringValue(v["value"]), Label: stringValue(v["label"])})
	}
	return out
}

func resourceDeclarationsToMaps(items []*contracts.ResourceDeclaration) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, compactMap(map[string]any{"name": item.GetName(), "context": item.GetContext(), "display_name": item.GetDisplayName(), "description": item.GetDescription(), "owner_plugin": item.GetOwnerPlugin(), "owner_module": item.GetOwnerModule(), "category": item.GetCategory(), "lookup_source_id": item.GetLookupSourceId()}))
	}
	return out
}

func actionDeclarationsToMaps(items []*contracts.ActionDeclaration) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, compactMap(map[string]any{"name": item.GetName(), "context": item.GetContext(), "resource": item.GetResource(), "description": item.GetDescription(), "owner_plugin": item.GetOwnerPlugin(), "owner_module": item.GetOwnerModule(), "category": item.GetCategory()}))
	}
	return out
}

func attributeDeclarationsToMaps(items []*contracts.AttributeDeclaration) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, compactMap(map[string]any{"name": item.GetName(), "context": item.GetContext(), "target": item.GetTarget(), "data_type": item.GetDataType(), "allowed_values": attributeValuesToMaps(item.GetAllowedValues()), "lookup_source_id": item.GetLookupSourceId(), "description": item.GetDescription(), "owner_plugin": item.GetOwnerPlugin(), "owner_module": item.GetOwnerModule(), "category": item.GetCategory()}))
	}
	return out
}

func relationDeclarationsToMaps(items []*contracts.RelationDeclaration) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, compactMap(map[string]any{"name": item.GetName(), "context": item.GetContext(), "subject_type": item.GetSubjectType(), "object_type": item.GetObjectType(), "description": item.GetDescription(), "owner_plugin": item.GetOwnerPlugin(), "owner_module": item.GetOwnerModule(), "category": item.GetCategory()}))
	}
	return out
}

func uiActionDeclarationsToMaps(items []*contracts.UIActionDeclaration) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, compactMap(map[string]any{"id": item.GetId(), "context": item.GetContext(), "label": item.GetLabel(), "route": item.GetRoute(), "required_scopes": stringsToAny(item.GetRequiredScopes()), "description": item.GetDescription(), "owner_plugin": item.GetOwnerPlugin(), "owner_module": item.GetOwnerModule(), "category": item.GetCategory()}))
	}
	return out
}

func attributeValuesToMaps(items []*contracts.AttributeValue) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, compactMap(map[string]any{"value": item.GetValue(), "label": item.GetLabel()}))
	}
	return out
}

func cloneDeclarationSet(set *contracts.AuthzDeclarationSet) *contracts.AuthzDeclarationSet {
	if set == nil {
		return &contracts.AuthzDeclarationSet{}
	}
	return &contracts.AuthzDeclarationSet{
		Scopes:      scopeDeclarationsFromAny(set.GetScopes(), set.GetOwnerPlugin(), set.GetOwnerModule()),
		Resources:   cloneResourceDeclarations(set.GetResources()),
		Actions:     cloneActionDeclarations(set.GetActions()),
		Attributes:  cloneAttributeDeclarations(set.GetAttributes()),
		Relations:   cloneRelationDeclarations(set.GetRelations()),
		UiActions:   cloneUIActionDeclarations(set.GetUiActions()),
		OwnerPlugin: set.GetOwnerPlugin(),
		OwnerModule: set.GetOwnerModule(),
	}
}

func cloneResourceDeclarations(items []*contracts.ResourceDeclaration) []*contracts.ResourceDeclaration {
	out := make([]*contracts.ResourceDeclaration, 0, len(items))
	for _, item := range items {
		out = append(out, cloneResourceDeclaration(item))
	}
	return out
}

func cloneResourceDeclaration(item *contracts.ResourceDeclaration) *contracts.ResourceDeclaration {
	if item == nil {
		return nil
	}
	clone := *item
	return &clone
}

func cloneActionDeclarations(items []*contracts.ActionDeclaration) []*contracts.ActionDeclaration {
	out := make([]*contracts.ActionDeclaration, 0, len(items))
	for _, item := range items {
		out = append(out, cloneActionDeclaration(item))
	}
	return out
}

func cloneActionDeclaration(item *contracts.ActionDeclaration) *contracts.ActionDeclaration {
	if item == nil {
		return nil
	}
	clone := *item
	return &clone
}

func cloneAttributeDeclarations(items []*contracts.AttributeDeclaration) []*contracts.AttributeDeclaration {
	out := make([]*contracts.AttributeDeclaration, 0, len(items))
	for _, item := range items {
		out = append(out, cloneAttributeDeclaration(item))
	}
	return out
}

func cloneAttributeDeclaration(item *contracts.AttributeDeclaration) *contracts.AttributeDeclaration {
	if item == nil {
		return nil
	}
	clone := *item
	clone.AllowedValues = cloneAttributeValues(item.GetAllowedValues())
	return &clone
}

func cloneAttributeValues(items []*contracts.AttributeValue) []*contracts.AttributeValue {
	out := make([]*contracts.AttributeValue, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		clone := *item
		out = append(out, &clone)
	}
	return out
}

func cloneRelationDeclarations(items []*contracts.RelationDeclaration) []*contracts.RelationDeclaration {
	out := make([]*contracts.RelationDeclaration, 0, len(items))
	for _, item := range items {
		out = append(out, cloneRelationDeclaration(item))
	}
	return out
}

func cloneRelationDeclaration(item *contracts.RelationDeclaration) *contracts.RelationDeclaration {
	if item == nil {
		return nil
	}
	clone := *item
	return &clone
}

func cloneUIActionDeclarations(items []*contracts.UIActionDeclaration) []*contracts.UIActionDeclaration {
	out := make([]*contracts.UIActionDeclaration, 0, len(items))
	for _, item := range items {
		out = append(out, cloneUIActionDeclaration(item))
	}
	return out
}

func cloneUIActionDeclaration(item *contracts.UIActionDeclaration) *contracts.UIActionDeclaration {
	if item == nil {
		return nil
	}
	clone := *item
	clone.RequiredScopes = append([]string(nil), item.GetRequiredScopes()...)
	clone.RequiredCapabilities = append([]*contracts.CapabilityRequirement(nil), item.GetRequiredCapabilities()...)
	return &clone
}

func sortDeclarationSet(set *contracts.AuthzDeclarationSet) {
	sortScopes(set.Scopes)
	sort.Slice(set.Resources, func(i, j int) bool { return set.Resources[i].GetName() < set.Resources[j].GetName() })
	sort.Slice(set.Actions, func(i, j int) bool {
		return actionKey(set.Actions[i].GetContext(), set.Actions[i].GetResource(), set.Actions[i].GetName()) < actionKey(set.Actions[j].GetContext(), set.Actions[j].GetResource(), set.Actions[j].GetName())
	})
	sort.Slice(set.Attributes, func(i, j int) bool { return set.Attributes[i].GetName() < set.Attributes[j].GetName() })
	sort.Slice(set.Relations, func(i, j int) bool {
		return relationKey(set.Relations[i].GetContext(), set.Relations[i].GetObjectType(), set.Relations[i].GetName()) < relationKey(set.Relations[j].GetContext(), set.Relations[j].GetObjectType(), set.Relations[j].GetName())
	})
	sort.Slice(set.UiActions, func(i, j int) bool { return set.UiActions[i].GetId() < set.UiActions[j].GetId() })
}

func resourceKey(contextName, name string) string { return contextName + "/" + name }

func actionKey(contextName, resource, name string) string {
	return contextName + "/" + resource + "/" + name
}

func attributeKey(contextName, name string) string { return contextName + "/" + name }

func relationKey(contextName, objectType, name string) string {
	return contextName + "/" + objectType + "/" + name
}

func uiActionKey(contextName, id string) string { return contextName + "/" + id }
