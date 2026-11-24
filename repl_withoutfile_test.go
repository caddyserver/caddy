package caddy

import "testing"

// The copy returned by WithoutFile shares the original's static map, so it
// must also share its mutex; a fresh nil mapMutex made any Set on the copy
// panic. See #8447.
func TestWithoutFileCopySetDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Set on file-less copy panicked: %v", r)
		}
	}()
	rep := NewReplacer()
	nf := rep.WithoutFile()
	nf.Set("b", "2")
	if got, _ := rep.Get("b"); got != "2" {
		t.Errorf("original sees %v, want \"2\" (the copy shares the static map)", got)
	}
}

// Every mutator on the copy has to lock the shared map, so each one must
// work on a file-less copy and be visible through the original.
func TestWithoutFileCopyMutators(t *testing.T) {
	rep := NewReplacer()
	rep.Set("a", "1")
	rep.Set("b", "2")
	rep.Set("keep", "3")

	nf := rep.WithoutFile()

	nf.Set("c", "4")
	if got, ok := rep.Get("c"); !ok || got != "4" {
		t.Errorf("after Set on copy, original sees %q/%v for \"c\", want \"4\"/true", got, ok)
	}

	nf.Delete("a")
	if _, ok := rep.Get("a"); ok {
		t.Error("Delete on copy left \"a\" visible through the original")
	}

	nf.DeleteByPrefix("b")
	if _, ok := rep.Get("b"); ok {
		t.Error("DeleteByPrefix on copy left \"b\" visible through the original")
	}
	if got, ok := rep.Get("keep"); !ok || got != "3" {
		t.Errorf("after DeleteByPrefix(\"b\"), \"keep\" is %q/%v, want \"3\"/true", got, ok)
	}
}
