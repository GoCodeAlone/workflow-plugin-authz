// Package authz provides engine-native factories for the Casbin RBAC module
// and pipeline steps. Import this package when embedding the authz plugin
// directly into an engine plugin (avoiding gRPC / duplicate step registration).
//
// Usage in a host plugin:
//
//	func (p *MyPlugin) ModuleFactories() map[string]plugin.ModuleFactory {
//	    return map[string]plugin.ModuleFactory{
//	        "authz.casbin": authz.NewCasbinModuleFactory(),
//	    }
//	}
//
//	func (p *MyPlugin) StepFactories() map[string]plugin.StepFactory {
//	    return authz.StepFactories()
//	}
package authz

import (
	"context"
	"fmt"

	"github.com/CrisisTextLine/modular"
	"github.com/GoCodeAlone/workflow/module"
	"github.com/GoCodeAlone/workflow/plugin"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal"
)

// casbinModuleWrapper adapts the internal CasbinModule (sdk.ModuleInstance)
// to the engine's modular.Module interface so it can be used with ModuleFactory.
type casbinModuleWrapper struct {
	name   string
	config map[string]any
	inner  *internal.CasbinModule
}

// NewCasbinModuleFactory returns an engine-compatible ModuleFactory for "authz.casbin".
func NewCasbinModuleFactory() plugin.ModuleFactory {
	return func(name string, config map[string]any) modular.Module {
		return &casbinModuleWrapper{name: name, config: config}
	}
}

func (m *casbinModuleWrapper) Name() string { return m.name }

func (m *casbinModuleWrapper) Init(app modular.Application) error {
	inner, err := internal.NewCasbinModuleFromConfig(m.name, m.config)
	if err != nil {
		return err
	}
	if err := inner.Init(); err != nil {
		return err
	}
	m.inner = inner
	// Register in the global step registry so steps can find the enforcer.
	internal.RegisterModule(inner)
	// Register as a service in the engine's service registry.
	return app.RegisterService(m.name, m)
}

func (m *casbinModuleWrapper) ProvidesServices() []modular.ServiceProvider {
	return []modular.ServiceProvider{
		{Name: m.name, Description: "Casbin RBAC: " + m.name, Instance: m},
	}
}

func (m *casbinModuleWrapper) RequiresServices() []modular.ServiceDependency { return nil }

func (m *casbinModuleWrapper) Start(ctx context.Context) error {
	if m.inner == nil {
		return nil
	}
	return m.inner.Start(ctx)
}

func (m *casbinModuleWrapper) Stop(ctx context.Context) error {
	if m.inner == nil {
		return nil
	}
	return m.inner.Stop(ctx)
}

// Enforce delegates to the inner CasbinModule.
func (m *casbinModuleWrapper) Enforce(sub, obj, act string) (bool, error) {
	if m.inner == nil {
		return false, fmt.Errorf("authz.casbin %q: not initialized", m.name)
	}
	return m.inner.Enforce(sub, obj, act)
}

// AddPolicy delegates to the inner CasbinModule.
func (m *casbinModuleWrapper) AddPolicy(rule []string) (bool, error) {
	if m.inner == nil {
		return false, fmt.Errorf("authz.casbin %q: not initialized", m.name)
	}
	return m.inner.AddPolicy(rule)
}

// RemovePolicy delegates to the inner CasbinModule.
func (m *casbinModuleWrapper) RemovePolicy(rule []string) (bool, error) {
	if m.inner == nil {
		return false, fmt.Errorf("authz.casbin %q: not initialized", m.name)
	}
	return m.inner.RemovePolicy(rule)
}

// --- Step Adapters ---

// stepAdapter wraps an internal sdk.StepInstance as an engine-native PipelineStep.
type stepAdapter struct {
	name  string
	inner internal.StepExecutor
}

func (s *stepAdapter) Name() string { return s.name }

func (s *stepAdapter) Execute(ctx context.Context, pc *module.PipelineContext) (*module.StepResult, error) {
	sdkResult, err := s.inner.Execute(ctx, pc.TriggerData, pc.StepOutputs, pc.Current, pc.Metadata, nil)
	if err != nil {
		return nil, err
	}
	return &module.StepResult{
		Output: sdkResult.Output,
		Stop:   sdkResult.StopPipeline,
	}, nil
}

// StepFactories returns all authz step factories as engine-native StepFactory values.
// Step types: step.authz_check_casbin, step.authz_add_policy, step.authz_remove_policy, step.authz_role_assign.
func StepFactories() map[string]plugin.StepFactory {
	return map[string]plugin.StepFactory{
		"step.authz_check_casbin":  newCasbinCheckFactory(),
		"step.authz_add_policy":    newAuthzAddPolicyFactory(),
		"step.authz_remove_policy": newAuthzRemovePolicyFactory(),
		"step.authz_role_assign":   newAuthzRoleAssignFactory(),
	}
}

func newCasbinCheckFactory() plugin.StepFactory {
	return func(name string, config map[string]any, _ modular.Application) (any, error) {
		inner, err := internal.NewCasbinCheckStep(name, config)
		if err != nil {
			return nil, err
		}
		return &stepAdapter{name: name, inner: inner}, nil
	}
}

func newAuthzAddPolicyFactory() plugin.StepFactory {
	return func(name string, config map[string]any, _ modular.Application) (any, error) {
		inner, err := internal.NewAddPolicyStep(name, config)
		if err != nil {
			return nil, err
		}
		return &stepAdapter{name: name, inner: inner}, nil
	}
}

func newAuthzRemovePolicyFactory() plugin.StepFactory {
	return func(name string, config map[string]any, _ modular.Application) (any, error) {
		inner, err := internal.NewRemovePolicyStep(name, config)
		if err != nil {
			return nil, err
		}
		return &stepAdapter{name: name, inner: inner}, nil
	}
}

func newAuthzRoleAssignFactory() plugin.StepFactory {
	return func(name string, config map[string]any, _ modular.Application) (any, error) {
		inner, err := internal.NewRoleAssignStep(name, config)
		if err != nil {
			return nil, err
		}
		return &stepAdapter{name: name, inner: inner}, nil
	}
}
