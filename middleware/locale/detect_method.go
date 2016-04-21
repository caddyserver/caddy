package locale

import (
	"fmt"
	"strings"
)

// Enum of the possible detect methods.
const (
	DetectMethodHeader DetectMethod = "header"
)

// DetectMethod defines a label for detect methods.
type DetectMethod string

// ParseDetectMethod returns a detect method based on the provided string.
func ParseDetectMethod(text string) (DetectMethod, error) {
	switch t := strings.ToLower(strings.TrimSpace(text)); t {
	case string(DetectMethodHeader):
		return DetectMethod(t), nil
	default:
		return DetectMethod(""), fmt.Errorf("unknown detect method [%s]", t)
	}
}
