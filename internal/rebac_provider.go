package internal

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

var errUnsupportedReBAC = errors.New("rebac provider is not supported by this module configuration")

type RelationshipProvider interface {
	Name() string
	UpsertRelationTuple(context.Context, RelationTuple) error
	RemoveRelationTuple(context.Context, RelationTuple) error
	ListRelationTuples(context.Context, RelationTupleFilter) ([]RelationTuple, error)
	CheckRelation(context.Context, RelationCheck) (RelationCheckResult, error)
}

type RelationTuple struct {
	Subject  string
	Relation string
	Object   string
	Context  string
}

type RelationTupleFilter struct {
	Subject  string
	Relation string
	Object   string
	Context  string
}

type RelationCheck struct {
	Subject  string
	Relation string
	Object   string
	Context  string
}

type RelationCheckResult struct {
	Allowed  bool
	Subject  string
	Relation string
	Object   string
	Context  string
	Reason   string
}

type relationTupleStore struct {
	mu     sync.RWMutex
	tuples map[string]RelationTuple
}

func newRelationTupleStore() *relationTupleStore {
	return &relationTupleStore{tuples: map[string]RelationTuple{}}
}

func (s *relationTupleStore) Upsert(tuple RelationTuple) error {
	tuple = normalizeRelationTuple(tuple)
	if err := validateRelationTuple(tuple); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tuples[relationTupleKey(tuple)] = tuple
	return nil
}

func (s *relationTupleStore) Remove(tuple RelationTuple) error {
	tuple = normalizeRelationTuple(tuple)
	if err := validateRelationTuple(tuple); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tuples, relationTupleKey(tuple))
	return nil
}

func (s *relationTupleStore) List(filter RelationTupleFilter) []RelationTuple {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RelationTuple, 0, len(s.tuples))
	for _, tuple := range s.tuples {
		if relationTupleMatches(tuple, filter) {
			out = append(out, tuple)
		}
	}
	sort.Slice(out, func(i, j int) bool { return relationTupleKey(out[i]) < relationTupleKey(out[j]) })
	return out
}

func (s *relationTupleStore) Contains(check RelationCheck) bool {
	filter := RelationTupleFilter{Subject: check.Subject, Relation: check.Relation, Object: check.Object, Context: check.Context}
	return len(s.List(filter)) > 0
}

func normalizeRelationTuple(tuple RelationTuple) RelationTuple {
	tuple.Subject = strings.TrimSpace(tuple.Subject)
	tuple.Relation = strings.TrimSpace(tuple.Relation)
	tuple.Object = strings.TrimSpace(tuple.Object)
	tuple.Context = strings.TrimSpace(tuple.Context)
	return tuple
}

func validateRelationTuple(tuple RelationTuple) error {
	if tuple.Subject == "" || tuple.Relation == "" || tuple.Object == "" || tuple.Context == "" {
		return fmt.Errorf("relation tuple requires subject, relation, object, and context")
	}
	return nil
}

func relationTupleMatches(tuple RelationTuple, filter RelationTupleFilter) bool {
	return (filter.Subject == "" || tuple.Subject == filter.Subject) &&
		(filter.Relation == "" || tuple.Relation == filter.Relation) &&
		(filter.Object == "" || tuple.Object == filter.Object) &&
		(filter.Context == "" || tuple.Context == filter.Context)
}

func relationTupleKey(tuple RelationTuple) string {
	return tuple.Context + "/" + tuple.Object + "/" + tuple.Relation + "/" + tuple.Subject
}

func upsertRelationTupleInvoke(ctx context.Context, provider RelationshipProvider, input map[string]any) (map[string]any, error) {
	tuple := relationTupleFromMap(mapValue(input["tuple"]))
	if err := provider.UpsertRelationTuple(ctx, tuple); err != nil {
		return nil, err
	}
	return map[string]any{"changed": true, "tuple": relationTupleToMap(tuple)}, nil
}

func listRelationTuplesInvoke(ctx context.Context, provider RelationshipProvider, input map[string]any) (map[string]any, error) {
	tuples, err := provider.ListRelationTuples(ctx, relationTupleFilterFromMap(mapValue(input["filter"])))
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(tuples))
	for _, tuple := range tuples {
		items = append(items, relationTupleToMap(tuple))
	}
	return map[string]any{"tuples": items}, nil
}

func removeRelationTupleInvoke(ctx context.Context, provider RelationshipProvider, input map[string]any) (map[string]any, error) {
	if err := provider.RemoveRelationTuple(ctx, relationTupleFromMap(mapValue(input["tuple"]))); err != nil {
		return nil, err
	}
	return map[string]any{"changed": true}, nil
}

func checkRelationInvoke(ctx context.Context, provider RelationshipProvider, input map[string]any) (map[string]any, error) {
	result, err := provider.CheckRelation(ctx, relationCheckFromMap(input))
	if err != nil {
		return relationCheckResultToMap(result), err
	}
	return relationCheckResultToMap(result), nil
}

func relationTupleFromMap(values map[string]any) RelationTuple {
	return RelationTuple{
		Subject:  stringValue(values["subject"]),
		Relation: stringValue(values["relation"]),
		Object:   stringValue(values["object"]),
		Context:  stringValue(values["context"]),
	}
}

func relationTupleFilterFromMap(values map[string]any) RelationTupleFilter {
	return RelationTupleFilter{
		Subject:  stringValue(values["subject"]),
		Relation: stringValue(values["relation"]),
		Object:   stringValue(values["object"]),
		Context:  stringValue(values["context"]),
	}
}

func relationCheckFromMap(values map[string]any) RelationCheck {
	return RelationCheck{
		Subject:  stringValue(values["subject"]),
		Relation: stringValue(values["relation"]),
		Object:   stringValue(values["object"]),
		Context:  stringValue(values["context"]),
	}
}

func relationTupleToMap(tuple RelationTuple) map[string]any {
	return compactMap(map[string]any{"subject": tuple.Subject, "relation": tuple.Relation, "object": tuple.Object, "context": tuple.Context})
}

func relationCheckResultToMap(result RelationCheckResult) map[string]any {
	return compactMap(map[string]any{
		"allowed":  result.Allowed,
		"subject":  result.Subject,
		"relation": result.Relation,
		"object":   result.Object,
		"context":  result.Context,
		"reason":   result.Reason,
	})
}
