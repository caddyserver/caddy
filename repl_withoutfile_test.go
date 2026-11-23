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
