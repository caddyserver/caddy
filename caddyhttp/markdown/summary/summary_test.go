package summary

import "testing"

func TestMarkdown(t *testing.T) {
	input := []byte(`Testing with just a few words.`)
	got := string(Markdown(input, 3))
	if want := "Testing with just"; want != got {
		t.Errorf("Expected '%s' but got '%s'", want, got)
	}
}
