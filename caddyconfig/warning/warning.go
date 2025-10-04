package warning

import "fmt"

// Warning represents a warning or notice related to conversion.
type Warning struct {
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	Directive string `json:"directive,omitempty"`
	Message   string `json:"message,omitempty"`
}

func (w Warning) String() string {
	var directive string
	if w.Directive != "" {
		directive = fmt.Sprintf(" (%s)", w.Directive)
	}
	return fmt.Sprintf("%s:%d%s: %s", w.File, w.Line, directive, w.Message)
}
