package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
)

type handler struct {
	options Options
	routes  RouteCatalog
	mux     *http.ServeMux
}

func NewHandler(options Options) (http.Handler, error) {
	options = normalizeOptions(options)
	if err := options.validate(); err != nil {
		return nil, err
	}
	h := &handler{options: options, routes: RoutesForBasePath(options.BasePath), mux: http.NewServeMux()}
	h.routes.install(h)
	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestPath := cleanPath(r.URL.Path)
	if route, ok := h.routes.ByPath[r.Method+" "+requestPath]; ok {
		h.dispatch(w, r, route)
		return
	}
	if h.isAdminAPIPath(requestPath) {
		if allow := h.allowedMethods(requestPath); len(allow) > 0 {
			w.Header().Set("Allow", strings.Join(allow, ", "))
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *handler) isAdminAPIPath(requestPath string) bool {
	basePath := h.options.BasePath
	return requestPath == basePath || strings.HasPrefix(requestPath, basePath+"/")
}

func (h *handler) allowedMethods(requestPath string) []string {
	known := map[string]bool{}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if _, ok := h.routes.ByPath[method+" "+requestPath]; ok {
			known[method] = true
		}
	}
	methods := make([]string, 0, len(known))
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if known[method] {
			methods = append(methods, method)
		}
	}
	return methods
}

func (c RouteCatalog) install(h *handler) {
	routesByPath := make(map[string][]Route)
	for key, route := range c.ByPath {
		if strings.Contains(key, " ") {
			routesByPath[route.Path] = append(routesByPath[route.Path], route)
		}
	}
	for routePath, routes := range routesByPath {
		routes := routes
		h.mux.HandleFunc(routePath, func(w http.ResponseWriter, r *http.Request) {
			for _, route := range routes {
				if route.Method == r.Method {
					h.dispatch(w, r, route)
					return
				}
			}
			allow := make([]string, 0, len(routes))
			for _, route := range routes {
				allow = append(allow, route.Method)
			}
			w.Header().Set("Allow", strings.Join(allow, ", "))
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		})
	}
}

func DefaultRoutes() RouteCatalog {
	return RoutesForBasePath("/api/authz")
}

func RoutesForBasePath(basePath string) RouteCatalog {
	basePath = cleanPath(basePath)
	routes := []Route{
		{Name: "roles", Method: http.MethodGet, Path: basePath + "/roles", Resource: "authz.roles", Action: "read"},
		{Name: "roles-upsert", Method: http.MethodPost, Path: basePath + "/roles", Resource: "authz.roles", Action: "update"},
		{Name: "roles-delete", Method: http.MethodDelete, Path: basePath + "/roles", Resource: "authz.roles", Action: "update"},
		{Name: "scopes", Method: http.MethodGet, Path: basePath + "/scopes", Resource: "authz.scopes", Action: "read"},
		{Name: "capabilities", Method: http.MethodGet, Path: basePath + "/capabilities", Resource: "authz.capabilities", Action: "read"},
		{Name: "declarations", Method: http.MethodGet, Path: basePath + "/declarations", Resource: "authz.declarations", Action: "read"},
		{Name: "projection-inputs", Method: http.MethodGet, Path: basePath + "/projection-inputs", Resource: "authz.projection", Action: "read"},
		{Name: "model", Method: http.MethodGet, Path: basePath + "/model", Resource: "authz.model", Action: "read"},
		{Name: "policies", Method: http.MethodGet, Path: basePath + "/policies", Resource: "authz.policies", Action: "read"},
		{Name: "policies-upsert", Method: http.MethodPost, Path: basePath + "/policies", Resource: "authz.policies", Action: "update"},
		{Name: "policies-delete", Method: http.MethodDelete, Path: basePath + "/policies", Resource: "authz.policies", Action: "update"},
		{Name: "abac-policies", Method: http.MethodGet, Path: basePath + "/abac/policies", Resource: "authz.abac.policies", Action: "read"},
		{Name: "abac-policies-upsert", Method: http.MethodPost, Path: basePath + "/abac/policies", Resource: "authz.abac.policies", Action: "update"},
		{Name: "abac-policies-delete", Method: http.MethodDelete, Path: basePath + "/abac/policies", Resource: "authz.abac.policies", Action: "update"},
		{Name: "rebac-tuples", Method: http.MethodGet, Path: basePath + "/rebac/tuples", Resource: "authz.rebac.tuples", Action: "read"},
		{Name: "rebac-tuples-upsert", Method: http.MethodPost, Path: basePath + "/rebac/tuples", Resource: "authz.rebac.tuples", Action: "update"},
		{Name: "rebac-tuples-delete", Method: http.MethodDelete, Path: basePath + "/rebac/tuples", Resource: "authz.rebac.tuples", Action: "update"},
		{Name: "rebac-check", Method: http.MethodPost, Path: basePath + "/rebac/check", Resource: "authz.rebac", Action: "check"},
		{Name: "enforce", Method: http.MethodPost, Path: basePath + "/enforce", Resource: "authz.decisions", Action: "enforce"},
	}
	byPath := make(map[string]Route, len(routes)*2)
	for _, route := range routes {
		byPath[route.Method+" "+route.Path] = route
		if _, exists := byPath[route.Path]; !exists || route.Method == http.MethodGet {
			byPath[route.Path] = route
		}
	}
	return RouteCatalog{ByPath: byPath}
}

func normalizeOptions(options Options) Options {
	if strings.TrimSpace(options.BasePath) == "" {
		options.BasePath = "/api/authz"
	}
	options.BasePath = cleanPath(options.BasePath)
	return options
}

func (o Options) validate() error {
	var missing []string
	if o.PrincipalResolver == nil {
		missing = append(missing, "PrincipalResolver")
	}
	if o.Authorizer == nil {
		missing = append(missing, "Authorizer")
	}
	if o.Provider == nil {
		missing = append(missing, "Provider")
	}
	if len(missing) > 0 {
		return fmt.Errorf("adminapi: missing required adapters: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (h *handler) dispatch(w http.ResponseWriter, r *http.Request, route Route) {
	if r.Method != route.Method {
		w.Header().Set("Allow", route.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	principal, ok := h.options.PrincipalResolver.CurrentPrincipal(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := h.options.Authorizer.Authorize(r.Context(), principal, route.Resource, route.Action); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.serveRoute(w, r, principal, route)
}

func (h *handler) serveRoute(w http.ResponseWriter, r *http.Request, principal Principal, route Route) {
	switch route.Name {
	case "roles":
		items, err := h.roleAssignments(r.Context(), principal)
		writeProviderResult(w, items, err)
	case "roles-upsert":
		var input RoleAssignment
		if !decodeRouteJSON(w, r, &input) {
			return
		}
		writeProviderResult(w, map[string]any{"changed": true}, h.options.Provider.UpsertRole(r.Context(), principal, input))
	case "roles-delete":
		var input RoleAssignment
		if !decodeRouteJSON(w, r, &input) {
			return
		}
		writeProviderResult(w, map[string]any{"changed": true}, h.options.Provider.DeleteRole(r.Context(), principal, input))
	case "scopes":
		items, err := h.options.Provider.Scopes(r.Context(), principal)
		writeProviderResult(w, items, err)
	case "capabilities":
		items, err := h.options.Provider.Capabilities(r.Context(), principal)
		writeProviderResult(w, map[string]any{"capabilities": items}, err)
	case "declarations":
		items, err := h.options.Provider.Declarations(r.Context(), principal)
		writeProviderResult(w, items, err)
	case "projection-inputs":
		items, err := h.options.Provider.ProjectionInputs(r.Context(), principal)
		writeProviderResult(w, items, err)
	case "model":
		item, err := h.options.Provider.Model(r.Context(), principal)
		writeProviderResult(w, item, err)
	case "policies":
		items, err := h.options.Provider.Policies(r.Context(), principal)
		writeProviderResult(w, items, err)
	case "policies-upsert":
		var input PolicyRule
		if !decodeRouteJSON(w, r, &input) {
			return
		}
		writeProviderResult(w, map[string]any{"changed": true}, h.options.Provider.UpsertPolicy(r.Context(), principal, input))
	case "policies-delete":
		var input PolicyRule
		if !decodeRouteJSON(w, r, &input) {
			return
		}
		writeProviderResult(w, map[string]any{"changed": true}, h.options.Provider.DeletePolicy(r.Context(), principal, input))
	case "abac-policies":
		items, err := h.options.Provider.AttributePolicies(r.Context(), principal)
		writeProviderResult(w, items, err)
	case "abac-policies-upsert":
		var input AttributePolicy
		if !decodeRouteJSON(w, r, &input) {
			return
		}
		writeProviderResult(w, map[string]any{"changed": true}, h.options.Provider.UpsertAttributePolicy(r.Context(), principal, input))
	case "abac-policies-delete":
		var input AttributePolicy
		if !decodeRouteJSON(w, r, &input) {
			return
		}
		writeProviderResult(w, map[string]any{"changed": true}, h.options.Provider.DeleteAttributePolicy(r.Context(), principal, input))
	case "rebac-tuples":
		items, err := h.options.Provider.RelationTuples(r.Context(), principal)
		writeProviderResult(w, items, err)
	case "rebac-tuples-upsert":
		var input RelationTuple
		if !decodeRouteJSON(w, r, &input) {
			return
		}
		writeProviderResult(w, map[string]any{"changed": true}, h.options.Provider.UpsertRelationTuple(r.Context(), principal, input))
	case "rebac-tuples-delete":
		var input RelationTuple
		if !decodeRouteJSON(w, r, &input) {
			return
		}
		writeProviderResult(w, map[string]any{"changed": true}, h.options.Provider.DeleteRelationTuple(r.Context(), principal, input))
	case "rebac-check":
		var input RelationCheck
		if err := decodeJSON(r, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		decision, err := h.options.Provider.CheckRelation(r.Context(), principal, input)
		writeProviderResult(w, decision, err)
	case "enforce":
		var input DecisionRequest
		if err := decodeJSON(r, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		decision, err := h.options.Provider.Enforce(r.Context(), principal, input)
		writeProviderResult(w, decision, err)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (h *handler) roleAssignments(ctx context.Context, principal Principal) ([]RoleAssignment, error) {
	if provider, ok := h.options.Provider.(RoleAssignmentProvider); ok {
		return provider.RoleAssignments(ctx, principal)
	}
	roles, err := h.options.Provider.Roles(ctx, principal)
	if err != nil {
		return nil, err
	}
	assignments := make([]RoleAssignment, 0, len(roles))
	for _, role := range roles {
		assignments = append(assignments, RoleAssignment{Role: role.Name, Scopes: role.Scopes})
	}
	return assignments, nil
}

func decodeRouteJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	if err := decodeJSON(r, out); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

func writeProviderResult(w http.ResponseWriter, payload any, err error) {
	if err != nil {
		if errors.Is(err, ErrInvalidRequest) {
			writeError(w, http.StatusBadRequest, "invalid authz request")
			return
		}
		writeError(w, http.StatusInternalServerError, "authz provider unavailable")
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

func cleanPath(value string) string {
	clean := path.Clean("/" + strings.Trim(strings.TrimSpace(value), "/"))
	if clean == "/" {
		return ""
	}
	return clean
}
