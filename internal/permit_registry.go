package internal

import "sync"

var (
	permitMu      sync.RWMutex
	permitClients = map[string]*permitClient{}
)

// RegisterPermitClient adds a permitClient to the global permit registry.
func RegisterPermitClient(name string, c *permitClient) {
	permitMu.Lock()
	defer permitMu.Unlock()
	permitClients[name] = c
}

// GetPermitClient retrieves a permitClient by module name.
func GetPermitClient(name string) (*permitClient, bool) {
	permitMu.RLock()
	defer permitMu.RUnlock()
	c, ok := permitClients[name]
	return c, ok
}

// UnregisterPermitClient removes a permitClient from the global permit registry.
func UnregisterPermitClient(name string) {
	permitMu.Lock()
	defer permitMu.Unlock()
	delete(permitClients, name)
}
