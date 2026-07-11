package v2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

const maxRequestBytes = 1 << 20

type route struct {
	method   string
	path     string
	resource string
	action   string
	serve    func(*handler, http.ResponseWriter, *http.Request, Principal)
}

type handler struct {
	options Options
	routes  map[string]route
	byPath  map[string][]string
}

// NewHandler returns the canonical read-only v2 authorization admin API.
func NewHandler(options Options) (http.Handler, error) {
	if strings.TrimSpace(options.BasePath) == "" {
		options.BasePath = "/api/authz"
	}
	options.BasePath = cleanPath(options.BasePath)
	var missing []string
	if options.PrincipalResolver == nil {
		missing = append(missing, "PrincipalResolver")
	}
	if options.Authorizer == nil {
		missing = append(missing, "Authorizer")
	}
	if options.Provider == nil {
		missing = append(missing, "Provider")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("adminapi/v2: missing required adapters: %s", strings.Join(missing, ", "))
	}

	h := &handler{options: options, routes: map[string]route{}, byPath: map[string][]string{}}
	h.add(http.MethodGet, "/principal", "authz.principal", "read", servePrincipal)
	h.add(http.MethodGet, "/capabilities", "authz.capabilities", "read", serveCapabilities)
	h.add(http.MethodGet, "/roles", "authz.roles", "read", serveRoles)
	h.add(http.MethodGet, "/policies", "authz.policies", "read", servePolicies)
	h.add(http.MethodPost, "/decision", "authz.decisions", "check", serveDecision)
	return h, nil
}

func (h *handler) add(method, suffix, resource, action string, serve func(*handler, http.ResponseWriter, *http.Request, Principal)) {
	r := route{method: method, path: h.options.BasePath + suffix, resource: resource, action: action, serve: serve}
	h.routes[method+" "+r.path] = r
	h.byPath[r.path] = append(h.byPath[r.path], method)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	requestPath := cleanPath(request.URL.Path)
	r, ok := h.routes[request.Method+" "+requestPath]
	if !ok {
		if methods := h.byPath[requestPath]; len(methods) > 0 {
			w.Header().Set("Allow", strings.Join(methods, ", "))
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	principal, err := h.options.PrincipalResolver.CurrentPrincipal(request)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if strings.TrimSpace(principal.Subject) == "" || strings.TrimSpace(principal.Role) == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := h.options.Authorizer.Authorize(request.Context(), principal, r.resource, r.action); err != nil {
		writeMappedError(w, err)
		return
	}
	r.serve(h, w, request, principal)
}

func servePrincipal(_ *handler, w http.ResponseWriter, _ *http.Request, principal Principal) {
	writeJSON(w, http.StatusOK, principal)
}

func serveCapabilities(h *handler, w http.ResponseWriter, request *http.Request, principal Principal) {
	payload, err := h.options.Provider.Capabilities(request.Context(), principal)
	if payload.Capabilities == nil {
		payload.Capabilities = []string{}
	}
	if payload.Descriptors == nil {
		payload.Descriptors = []CapabilityDescriptor{}
	}
	writeProviderResult(w, payload, err)
}

func serveRoles(h *handler, w http.ResponseWriter, request *http.Request, principal Principal) {
	payload, err := h.options.Provider.RoleAssignments(request.Context(), principal)
	if payload == nil {
		payload = []RoleAssignment{}
	}
	writeProviderResult(w, payload, err)
}

func servePolicies(h *handler, w http.ResponseWriter, request *http.Request, principal Principal) {
	payload, err := h.options.Provider.Policies(request.Context(), principal)
	if payload == nil {
		payload = []PolicyRule{}
	}
	writeProviderResult(w, payload, err)
}

func serveDecision(h *handler, w http.ResponseWriter, request *http.Request, principal Principal) {
	var input DecisionRequest
	if err := decodeJSON(w, request, &input); err != nil || strings.TrimSpace(input.Object) == "" || strings.TrimSpace(input.Action) == "" {
		writeError(w, http.StatusBadRequest, "invalid authz request")
		return
	}
	payload, err := h.options.Provider.Decide(request.Context(), principal, input)
	writeProviderResult(w, payload, err)
}

func decodeJSON(w http.ResponseWriter, request *http.Request, output any) error {
	request.Body = http.MaxBytesReader(w, request.Body, maxRequestBytes)
	defer func() { _ = request.Body.Close() }()
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func writeProviderResult(w http.ResponseWriter, payload any, err error) {
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func writeMappedError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		writeError(w, http.StatusBadRequest, "invalid authz request")
	case errors.Is(err, ErrUnauthenticated):
		writeError(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "authz provider unavailable")
	default:
		writeError(w, http.StatusServiceUnavailable, "authz provider unavailable")
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func cleanPath(value string) string {
	clean := path.Clean("/" + strings.Trim(strings.TrimSpace(value), "/"))
	if clean == "/" {
		return ""
	}
	return clean
}
