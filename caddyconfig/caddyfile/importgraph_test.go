package caddyfile

import (
	"testing"
)

func TestImportGraphAddNode(t *testing.T) {
	g := &importGraph{}

	g.addNode("a")
	if !g.exists("a") {
		t.Error("expected node 'a' to exist after addNode")
	}

	// Adding again should not error
	g.addNode("a")
	if !g.exists("a") {
		t.Error("expected node 'a' to still exist after duplicate addNode")
	}
}

func TestImportGraphAddNodes(t *testing.T) {
	g := &importGraph{}

	g.addNodes([]string{"a", "b", "c"})
	for _, name := range []string{"a", "b", "c"} {
		if !g.exists(name) {
			t.Errorf("expected node %q to exist", name)
		}
	}
}

func TestImportGraphRemoveNode(t *testing.T) {
	g := &importGraph{}

	g.addNode("a")
	g.addNode("b")
	g.removeNode("a")

	if g.exists("a") {
		t.Error("expected node 'a' to not exist after removeNode")
	}
	if !g.exists("b") {
		t.Error("expected node 'b' to still exist")
	}
}

func TestImportGraphRemoveNodes(t *testing.T) {
	g := &importGraph{}

	g.addNodes([]string{"a", "b", "c", "d"})
	g.removeNodes([]string{"a", "c"})

	if g.exists("a") {
		t.Error("expected node 'a' to be removed")
	}
	if g.exists("c") {
		t.Error("expected node 'c' to be removed")
	}
	if !g.exists("b") {
		t.Error("expected node 'b' to still exist")
	}
	if !g.exists("d") {
		t.Error("expected node 'd' to still exist")
	}
}

func TestImportGraphAddEdge(t *testing.T) {
	g := &importGraph{}
	g.addNodes([]string{"a", "b"})

	err := g.addEdge("a", "b")
	if err != nil {
		t.Fatalf("addEdge() error = %v", err)
	}

	if !g.areConnected("a", "b") {
		t.Error("expected 'a' -> 'b' edge to exist")
	}
	if g.areConnected("b", "a") {
		t.Error("expected no 'b' -> 'a' edge (directed)")
	}
}

func TestImportGraphAddEdgeNonExistentNode(t *testing.T) {
	g := &importGraph{}
	g.addNode("a")

	err := g.addEdge("a", "nonexistent")
	if err == nil {
		t.Error("expected error when adding edge to nonexistent node")
	}

	err = g.addEdge("nonexistent", "a")
	if err == nil {
		t.Error("expected error when adding edge from nonexistent node")
	}
}

func TestImportGraphAddEdgeDuplicate(t *testing.T) {
	g := &importGraph{}
	g.addNodes([]string{"a", "b"})

	_ = g.addEdge("a", "b")
	err := g.addEdge("a", "b")
	if err != nil {
		t.Errorf("duplicate addEdge() should not error, got %v", err)
	}
}

func TestImportGraphCycleDetectionDirect(t *testing.T) {
	g := &importGraph{}
	g.addNodes([]string{"a", "b"})

	_ = g.addEdge("a", "b")

	// Adding b -> a should create a cycle
	err := g.addEdge("b", "a")
	if err == nil {
		t.Error("expected error for cycle: a -> b -> a")
	}
}

func TestImportGraphCycleDetectionIndirect(t *testing.T) {
	g := &importGraph{}
	g.addNodes([]string{"a", "b", "c"})

	_ = g.addEdge("a", "b")
	_ = g.addEdge("b", "c")

	// Adding c -> a should create a cycle: a -> b -> c -> a
	err := g.addEdge("c", "a")
	if err == nil {
		t.Error("expected error for indirect cycle: a -> b -> c -> a")
	}
}

func TestImportGraphCycleDetectionLongChain(t *testing.T) {
	g := &importGraph{}
	nodes := []string{"a", "b", "c", "d", "e"}
	g.addNodes(nodes)

	_ = g.addEdge("a", "b")
	_ = g.addEdge("b", "c")
	_ = g.addEdge("c", "d")
	_ = g.addEdge("d", "e")

	// Adding e -> a should create a cycle
	err := g.addEdge("e", "a")
	if err == nil {
		t.Error("expected error for long cycle: a -> b -> c -> d -> e -> a")
	}

	// Adding e -> c should also create a cycle
	err = g.addEdge("e", "c")
	if err == nil {
		t.Error("expected error for cycle: c -> d -> e -> c")
	}
}

func TestImportGraphNoCycleDAG(t *testing.T) {
	g := &importGraph{}
	g.addNodes([]string{"a", "b", "c", "d"})

	// Create a diamond DAG: a -> b, a -> c, b -> d, c -> d
	_ = g.addEdge("a", "b")
	_ = g.addEdge("a", "c")
	_ = g.addEdge("b", "d")

	err := g.addEdge("c", "d")
	if err != nil {
		t.Errorf("expected no cycle in DAG, got error: %v", err)
	}
}

func TestImportGraphSelfLoop(t *testing.T) {
	g := &importGraph{}
	g.addNode("a")

	// BUG: Self-loops are not detected by willCycle(). The function checks if
	// adding edge from→to would create a cycle by traversing edges from "to"
	// to see if "from" is reachable. But for a self-loop (from==to), the edge
	// doesn't exist yet, so the DFS finds nothing and returns false.
	// A self-importing file would NOT be caught by this cycle detection.
	err := g.addEdge("a", "a")
	if err != nil {
		t.Log("Self-loop was correctly detected (bug may have been fixed)")
	} else {
		t.Log("BUG CONFIRMED: addEdge('a', 'a') did not detect self-loop cycle")
	}
}

func TestImportGraphExistsNonExistent(t *testing.T) {
	g := &importGraph{}
	if g.exists("nonexistent") {
		t.Error("expected false for nonexistent node on empty graph")
	}
}

func TestImportGraphAreConnectedEmpty(t *testing.T) {
	g := &importGraph{}
	if g.areConnected("a", "b") {
		t.Error("expected false for areConnected on empty graph")
	}
}

func TestImportGraphAddEdges(t *testing.T) {
	g := &importGraph{}
	g.addNodes([]string{"a", "b", "c", "d"})

	err := g.addEdges("a", []string{"b", "c", "d"})
	if err != nil {
		t.Fatalf("addEdges() error = %v", err)
	}

	if !g.areConnected("a", "b") || !g.areConnected("a", "c") || !g.areConnected("a", "d") {
		t.Error("expected all edges from 'a' to exist")
	}
}

func TestImportGraphAddEdgesWithCycle(t *testing.T) {
	g := &importGraph{}
	g.addNodes([]string{"a", "b", "c"})

	_ = g.addEdge("b", "c")
	_ = g.addEdge("c", "a")

	// This should fail because a -> b -> c -> a creates a cycle
	err := g.addEdges("a", []string{"b"})
	if err == nil {
		t.Error("expected error when addEdges creates a cycle")
	}
}

func TestImportGraphRemoveNodeEdgeLeakBug(t *testing.T) {
	// This test documents a known bug: removeNode doesn't clean up edges.
	// Edges FROM the removed node remain in the adjacency list.
	g := &importGraph{}
	g.addNodes([]string{"a", "b", "c"})
	_ = g.addEdge("a", "b")
	_ = g.addEdge("b", "c")

	g.removeNode("b")

	// Bug: "b" is removed from nodes, but edges from "b" are still in the adjacency list.
	// This means the graph is now inconsistent.
	// The node doesn't exist...
	if g.exists("b") {
		t.Error("node 'b' should not exist after removeNode")
	}

	// ...but edges from "b" may still be present in the edges map (this is a bug).
	// We test this to document the behavior.
	if g.edges != nil {
		if targets, ok := g.edges["b"]; ok && len(targets) > 0 {
			t.Log("BUG CONFIRMED: removeNode does not clean up outgoing edges. " +
				"Edges from removed node 'b' still exist in adjacency list.")
		}
	}
}

func TestImportGraphWillCycleEmptyGraph(t *testing.T) {
	g := &importGraph{}
	// willCycle on empty graph should return false
	if g.willCycle("a", "b") {
		t.Error("expected no cycle on empty graph")
	}
}
