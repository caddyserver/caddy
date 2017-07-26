package toml

import (
	"fmt"
	"io"
	"reflect"
	"strings"

	stringutil "github.com/naoina/go-stringutil"
	"github.com/naoina/toml/ast"
)

// Config contains options for encoding and decoding.
type Config struct {
	// NormFieldName is used to match TOML keys to struct fields. The function runs for
	// both input keys and struct field names and should return a string that makes the
	// two match. You must set this field to use the decoder.
	//
	// Example: The function in the default config removes _ and lowercases all keys. This
	// allows a key called 'api_key' to match the struct field 'APIKey' because both are
	// normalized to 'apikey'.
	//
	// Note that NormFieldName is not used for fields which define a TOML
	// key through the struct tag.
	NormFieldName func(typ reflect.Type, keyOrField string) string

	// FieldToKey determines the TOML key of a struct field when encoding.
	// You must set this field to use the encoder.
	//
	// Note that FieldToKey is not used for fields which define a TOML
	// key through the struct tag.
	FieldToKey func(typ reflect.Type, field string) string

	// MissingField, if non-nil, is called when the decoder encounters a key for which no
	// matching struct field exists. The default behavior is to return an error.
	MissingField func(typ reflect.Type, key string) error
}

// DefaultConfig contains the default options for encoding and decoding.
// Snake case (i.e. 'foo_bar') is used for key names.
var DefaultConfig = Config{
	NormFieldName: defaultNormFieldName,
	FieldToKey:    snakeCase,
}

func defaultNormFieldName(typ reflect.Type, s string) string {
	return strings.Replace(strings.ToLower(s), "_", "", -1)
}

func snakeCase(typ reflect.Type, s string) string {
	return stringutil.ToSnakeCase(s)
}

func defaultMissingField(typ reflect.Type, key string) error {
	return fmt.Errorf("field corresponding to `%s' is not defined in %v", key, typ)
}

// NewEncoder returns a new Encoder that writes to w.
// It is shorthand for DefaultConfig.NewEncoder(w).
func NewEncoder(w io.Writer) *Encoder {
	return DefaultConfig.NewEncoder(w)
}

// Marshal returns the TOML encoding of v.
// It is shorthand for DefaultConfig.Marshal(v).
func Marshal(v interface{}) ([]byte, error) {
	return DefaultConfig.Marshal(v)
}

// Unmarshal parses the TOML data and stores the result in the value pointed to by v.
// It is shorthand for DefaultConfig.Unmarshal(data, v).
func Unmarshal(data []byte, v interface{}) error {
	return DefaultConfig.Unmarshal(data, v)
}

// UnmarshalTable applies the contents of an ast.Table to the value pointed at by v.
// It is shorthand for DefaultConfig.UnmarshalTable(t, v).
func UnmarshalTable(t *ast.Table, v interface{}) error {
	return DefaultConfig.UnmarshalTable(t, v)
}

// NewDecoder returns a new Decoder that reads from r.
// It is shorthand for DefaultConfig.NewDecoder(r).
func NewDecoder(r io.Reader) *Decoder {
	return DefaultConfig.NewDecoder(r)
}
