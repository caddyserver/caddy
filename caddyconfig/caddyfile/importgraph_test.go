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

import "testing"

func TestImportGraphSelfLoop(t *testing.T) {
	g := &importGraph{}
	g.addNode("a")

	if err := g.addEdge("a", "a"); err == nil {
		t.Error("expected error for self-loop cycle a -> a")
	}
}

func TestImportGraphRemoveNodeCleansEdges(t *testing.T) {
	g := &importGraph{}
	g.addNodes([]string{"a", "b", "c"})
	_ = g.addEdge("a", "b")
	_ = g.addEdge("b", "c")

	g.removeNode("b")

	if g.exists("b") {
		t.Error("node 'b' should not exist after removeNode")
	}
	if targets, ok := g.edges["b"]; ok && len(targets) > 0 {
		t.Errorf("outgoing edges from removed node 'b' should be cleared, got %v", targets)
	}
	if g.areConnected("a", "b") {
		t.Error("incoming edge 'a' -> 'b' should be removed when 'b' is removed")
	}
}
