package caddy

import (
	"fmt"
	"reflect"
)

var namespaceTypes map[string][]reflect.Type = make(map[string][]reflect.Type)

func RegisterType(namespace string, types []reflect.Type) {
	if _, ok := namespaceTypes[namespace]; ok {
		panic("namespace is already registered")
	}
	namespaceTypes[namespace] = types
}

// NamespaceTypes returns a copy of Caddy's namespace->type registry
func NamespaceTypes() map[string][]reflect.Type {
	copy := make(map[string][]reflect.Type)
	for namespace, typeSlice := range namespaceTypes {
		copy[namespace] = typeSlice
	}
	return copy
}

// ConformsToNamespace validates the given module implements all the mandatory types of a given namespace
func ConformsToNamespace(mod Module, namespace string) (bool, error) {
	modType := reflect.TypeOf(mod)
	for _, t := range namespaceTypes[namespace] {
		if !modType.Implements(t) {
			return false, fmt.Errorf("%s does not implement %s", modType, t)
		}
	}
	return true, nil
}
