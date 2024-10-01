// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyfile

import (
	"fmt"
	"slices"
)

type adjacency map[string][]string

type importGraph struct {
	nodes map[string]struct{}
	edges adjacency
}

func (i *importGraph) addNode(name string) {
	if i.nodes == nil {
		i.nodes = make(map[string]struct{})
	}
	if _, exists := i.nodes[name]; exists {
		return
	}
	i.nodes[name] = struct{}{}
}

func (i *importGraph) addNodes(names []string) {
	for _, name := range names {
		i.addNode(name)
	}
}

func (i *importGraph) removeNode(name string) {
	delete(i.nodes, name)
}

func (i *importGraph) removeNodes(names []string) {
	for _, name := range names {
		i.removeNode(name)
	}
}

func (i *importGraph) addEdge(from, to string) error {
	if !i.exists(from) || !i.exists(to) {
		return fmt.Errorf("one of the nodes does not exist")
	}

	if i.willCycle(to, from) {
		return fmt.Errorf("a cycle of imports exists between %s and %s", from, to)
	}

	if i.areConnected(from, to) {
		// if connected, there's nothing to do
		return nil
	}

	if i.nodes == nil {
		i.nodes = make(map[string]struct{})
	}
	if i.edges == nil {
		i.edges = make(adjacency)
	}

	i.edges[from] = append(i.edges[from], to)
	return nil
}

func (i *importGraph) addEdges(from string, tos []string) error {
	for _, to := range tos {
		err := i.addEdge(from, to)
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *importGraph) areConnected(from, to string) bool {
	al, ok := i.edges[from]
	if !ok {
		return false
	}
	return slices.Contains(al, to)
}

func (i *importGraph) willCycle(from, to string) bool {
	collector := make(map[string]bool)

	var visit func(string)
	visit = func(start string) {
		if !collector[start] {
			collector[start] = true
			for _, v := range i.edges[start] {
				visit(v)
			}
		}
	}

	for _, v := range i.edges[from] {
		visit(v)
	}
	for k := range collector {
		if to == k {
			return true
		}
	}

	return false
}

func (i *importGraph) exists(key string) bool {
	_, exists := i.nodes[key]
	return exists
}
