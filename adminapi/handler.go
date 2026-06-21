package adminapi

import (
	"encoding/json"
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
	h.mux.ServeHTTP(w, r)
}

func (c RouteCatalog) install(h *handler) {
	for _, route := range c.ByPath {
		route := route
		h.mux.HandleFunc(route.Path, func(w http.ResponseWriter, r *http.Request) {
			h.dispatch(w, r, route)
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
		{Name: "scopes", Method: http.MethodGet, Path: basePath + "/scopes", Resource: "authz.scopes", Action: "read"},
		{Name: "capabilities", Method: http.MethodGet, Path: basePath + "/capabilities", Resource: "authz.capabilities", Action: "read"},
		{Name: "declarations", Method: http.MethodGet, Path: basePath + "/declarations", Resource: "authz.declarations", Action: "read"},
		{Name: "projection-inputs", Method: http.MethodGet, Path: basePath + "/projection-inputs", Resource: "authz.projection", Action: "read"},
		{Name: "model", Method: http.MethodGet, Path: basePath + "/model", Resource: "authz.model", Action: "read"},
		{Name: "policies", Method: http.MethodGet, Path: basePath + "/policies", Resource: "authz.policies", Action: "read"},
		{Name: "abac-policies", Method: http.MethodGet, Path: basePath + "/abac/policies", Resource: "authz.abac.policies", Action: "read"},
		{Name: "rebac-tuples", Method: http.MethodGet, Path: basePath + "/rebac/tuples", Resource: "authz.rebac.tuples", Action: "read"},
		{Name: "rebac-check", Method: http.MethodPost, Path: basePath + "/rebac/check", Resource: "authz.rebac", Action: "check"},
		{Name: "enforce", Method: http.MethodPost, Path: basePath + "/enforce", Resource: "authz.decisions", Action: "enforce"},
	}
	byPath := make(map[string]Route, len(routes))
	for _, route := range routes {
		byPath[route.Path] = route
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
		items, err := h.options.Provider.Roles(r.Context(), principal)
		writeProviderResult(w, map[string]any{"roles": items}, err)
	case "scopes":
		items, err := h.options.Provider.Scopes(r.Context(), principal)
		writeProviderResult(w, map[string]any{"scopes": items}, err)
	case "capabilities":
		items, err := h.options.Provider.Capabilities(r.Context(), principal)
		writeProviderResult(w, map[string]any{"capabilities": items}, err)
	case "declarations":
		items, err := h.options.Provider.Declarations(r.Context(), principal)
		writeProviderResult(w, map[string]any{"declarations": items}, err)
	case "projection-inputs":
		items, err := h.options.Provider.ProjectionInputs(r.Context(), principal)
		writeProviderResult(w, map[string]any{"projection_inputs": items}, err)
	case "model":
		item, err := h.options.Provider.Model(r.Context(), principal)
		writeProviderResult(w, map[string]any{"model": item}, err)
	case "policies":
		items, err := h.options.Provider.Policies(r.Context(), principal)
		writeProviderResult(w, map[string]any{"policies": items}, err)
	case "abac-policies":
		items, err := h.options.Provider.AttributePolicies(r.Context(), principal)
		writeProviderResult(w, map[string]any{"policies": items}, err)
	case "rebac-tuples":
		items, err := h.options.Provider.RelationTuples(r.Context(), principal)
		writeProviderResult(w, map[string]any{"tuples": items}, err)
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

func writeProviderResult(w http.ResponseWriter, payload any, err error) {
	if err != nil {
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
