package toml

import (
	"bytes"
	"encoding"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/naoina/toml/ast"
)

const (
	tagOmitempty = "omitempty"
	tagSkip      = "-"
)

// Marshal returns the TOML encoding of v.
//
// Struct values encode as TOML. Each exported struct field becomes a field of
// the TOML structure unless
//   - the field's tag is "-", or
//   - the field is empty and its tag specifies the "omitempty" option.
//
// The "toml" key in the struct field's tag value is the key name, followed by
// an optional comma and options. Examples:
//
//   // Field is ignored by this package.
//   Field int `toml:"-"`
//
//   // Field appears in TOML as key "myName".
//   Field int `toml:"myName"`
//
//   // Field appears in TOML as key "myName" and the field is omitted from the
//   // result of encoding if its value is empty.
//   Field int `toml:"myName,omitempty"`
//
//   // Field appears in TOML as key "field", but the field is skipped if
//   // empty. Note the leading comma.
//   Field int `toml:",omitempty"`
func (cfg *Config) Marshal(v interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := cfg.NewEncoder(buf).Encode(v)
	return buf.Bytes(), err
}

// A Encoder writes TOML to an output stream.
type Encoder struct {
	w   io.Writer
	cfg *Config
}

// NewEncoder returns a new Encoder that writes to w.
func (cfg *Config) NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w, cfg}
}

// Encode writes the TOML of v to the stream.
// See the documentation for Marshal for details about the conversion of Go values to TOML.
func (e *Encoder) Encode(v interface{}) error {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return &marshalNilError{rv.Type()}
		}
		rv = rv.Elem()
	}
	buf := &tableBuf{typ: ast.TableTypeNormal}
	var err error
	switch rv.Kind() {
	case reflect.Struct:
		err = buf.structFields(e.cfg, rv)
	case reflect.Map:
		err = buf.mapFields(e.cfg, rv)
	default:
		err = &marshalTableError{rv.Type()}
	}
	if err != nil {
		return err
	}
	return buf.writeTo(e.w, "")
}

// Marshaler can be implemented to override the encoding of TOML values. The returned text
// must be a simple TOML value (i.e. not a table) and is inserted into marshaler output.
//
// This interface exists for backwards-compatibility reasons. You probably want to
// implement encoding.TextMarshaler or MarshalerRec instead.
type Marshaler interface {
	MarshalTOML() ([]byte, error)
}

// MarshalerRec can be implemented to override the TOML encoding of a type.
// The returned value is marshaled in place of the receiver.
type MarshalerRec interface {
	MarshalTOML() (interface{}, error)
}

type tableBuf struct {
	name       string // already escaped / quoted
	body       []byte
	children   []*tableBuf
	typ        ast.TableType
	arrayDepth int
}

func (b *tableBuf) writeTo(w io.Writer, prefix string) error {
	key := b.name // TODO: escape dots
	if prefix != "" {
		key = prefix + "." + key
	}

	if b.name != "" {
		head := "[" + key + "]"
		if b.typ == ast.TableTypeArray {
			head = "[" + head + "]"
		}
		head += "\n"
		if _, err := io.WriteString(w, head); err != nil {
			return err
		}
	}
	if _, err := w.Write(b.body); err != nil {
		return err
	}

	for i, child := range b.children {
		if len(b.body) > 0 || i > 0 {
			if _, err := w.Write([]byte("\n")); err != nil {
				return err
			}
		}
		if err := child.writeTo(w, key); err != nil {
			return err
		}
	}
	return nil
}

func (b *tableBuf) newChild(name string) *tableBuf {
	child := &tableBuf{name: quoteName(name), typ: ast.TableTypeNormal}
	if b.arrayDepth > 0 {
		child.typ = ast.TableTypeArray
	}
	return child
}

func (b *tableBuf) addChild(child *tableBuf) {
	// Empty table elision: we can avoid writing a table that doesn't have any keys on its
	// own. Array tables can't be elided because they define array elements (which would
	// be missing if elided).
	if len(child.body) == 0 && child.typ == ast.TableTypeNormal {
		for _, gchild := range child.children {
			gchild.name = child.name + "." + gchild.name
			b.addChild(gchild)
		}
		return
	}
	b.children = append(b.children, child)
}

func (b *tableBuf) structFields(cfg *Config, rv reflect.Value) error {
	rt := rv.Type()
	for i := 0; i < rv.NumField(); i++ {
		ft := rt.Field(i)
		if ft.PkgPath != "" && !ft.Anonymous { // not exported
			continue
		}
		name, rest := extractTag(ft.Tag.Get(fieldTagName))
		if name == tagSkip {
			continue
		}
		fv := rv.Field(i)
		if rest == tagOmitempty && isEmptyValue(fv) {
			continue
		}
		if name == "" {
			name = cfg.FieldToKey(rt, ft.Name)
		}
		if err := b.field(cfg, name, fv); err != nil {
			return err
		}
	}
	return nil
}

type mapKeyList []struct {
	key   string
	value reflect.Value
}

func (l mapKeyList) Len() int           { return len(l) }
func (l mapKeyList) Swap(i, j int)      { l[i], l[j] = l[j], l[i] }
func (l mapKeyList) Less(i, j int) bool { return l[i].key < l[j].key }

func (b *tableBuf) mapFields(cfg *Config, rv reflect.Value) error {
	keys := rv.MapKeys()
	keylist := make(mapKeyList, len(keys))
	for i, key := range keys {
		var err error
		keylist[i].key, err = encodeMapKey(key)
		if err != nil {
			return err
		}
		keylist[i].value = rv.MapIndex(key)
	}
	sort.Sort(keylist)

	for _, kv := range keylist {
		if err := b.field(cfg, kv.key, kv.value); err != nil {
			return err
		}
	}
	return nil
}

func (b *tableBuf) field(cfg *Config, name string, rv reflect.Value) error {
	off := len(b.body)
	b.body = append(b.body, quoteName(name)...)
	b.body = append(b.body, " = "...)
	isTable, err := b.value(cfg, rv, name)
	if isTable {
		b.body = b.body[:off] // rub out "key ="
	} else {
		b.body = append(b.body, '\n')
	}
	return err
}

func (b *tableBuf) value(cfg *Config, rv reflect.Value, name string) (bool, error) {
	isMarshaler, isTable, err := b.marshaler(cfg, rv, name)
	if isMarshaler {
		return isTable, err
	}
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		b.body = strconv.AppendInt(b.body, rv.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		b.body = strconv.AppendUint(b.body, rv.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		b.body = strconv.AppendFloat(b.body, rv.Float(), 'e', -1, 64)
	case reflect.Bool:
		b.body = strconv.AppendBool(b.body, rv.Bool())
	case reflect.String:
		b.body = strconv.AppendQuote(b.body, rv.String())
	case reflect.Ptr, reflect.Interface:
		if rv.IsNil() {
			return false, &marshalNilError{rv.Type()}
		}
		return b.value(cfg, rv.Elem(), name)
	case reflect.Slice, reflect.Array:
		rvlen := rv.Len()
		if rvlen == 0 {
			b.body = append(b.body, '[', ']')
			return false, nil
		}

		b.arrayDepth++
		wroteElem := false
		b.body = append(b.body, '[')
		for i := 0; i < rvlen; i++ {
			isTable, err := b.value(cfg, rv.Index(i), name)
			if err != nil {
				return isTable, err
			}
			wroteElem = wroteElem || !isTable
			if wroteElem {
				if i < rvlen-1 {
					b.body = append(b.body, ',', ' ')
				} else {
					b.body = append(b.body, ']')
				}
			}
		}
		if !wroteElem {
			b.body = b.body[:len(b.body)-1] // rub out '['
		}
		b.arrayDepth--
		return !wroteElem, nil
	case reflect.Struct:
		child := b.newChild(name)
		err := child.structFields(cfg, rv)
		b.addChild(child)
		return true, err
	case reflect.Map:
		child := b.newChild(name)
		err := child.mapFields(cfg, rv)
		b.addChild(child)
		return true, err
	default:
		return false, fmt.Errorf("toml: marshal: unsupported type %v", rv.Kind())
	}
	return false, nil
}

func (b *tableBuf) marshaler(cfg *Config, rv reflect.Value, name string) (handled, isTable bool, err error) {
	switch t := rv.Interface().(type) {
	case encoding.TextMarshaler:
		enc, err := t.MarshalText()
		if err != nil {
			return true, false, err
		}
		b.body = encodeTextMarshaler(b.body, string(enc))
		return true, false, nil
	case MarshalerRec:
		newval, err := t.MarshalTOML()
		if err != nil {
			return true, false, err
		}
		isTable, err = b.value(cfg, reflect.ValueOf(newval), name)
		return true, isTable, err
	case Marshaler:
		enc, err := t.MarshalTOML()
		if err != nil {
			return true, false, err
		}
		b.body = append(b.body, enc...)
		return true, false, nil
	}
	return false, false, nil
}

func encodeTextMarshaler(buf []byte, v string) []byte {
	// Emit the value without quotes if possible.
	if v == "true" || v == "false" {
		return append(buf, v...)
	} else if _, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return append(buf, v...)
	} else if _, err := strconv.ParseInt(v, 10, 64); err == nil {
		return append(buf, v...)
	} else if _, err := strconv.ParseUint(v, 10, 64); err == nil {
		return append(buf, v...)
	} else if _, err := strconv.ParseFloat(v, 64); err == nil {
		return append(buf, v...)
	}
	return strconv.AppendQuote(buf, v)
}

func encodeMapKey(rv reflect.Value) (string, error) {
	if rv.Kind() == reflect.String {
		return rv.String(), nil
	}
	if tm, ok := rv.Interface().(encoding.TextMarshaler); ok {
		b, err := tm.MarshalText()
		return string(b), err
	}
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(rv.Uint(), 10), nil
	}
	return "", fmt.Errorf("toml: invalid map key type %v", rv.Type())
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array:
		// encoding/json treats all arrays with non-zero length as non-empty. We check the
		// array content here because zero-length arrays are almost never used.
		len := v.Len()
		for i := 0; i < len; i++ {
			if !isEmptyValue(v.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

func quoteName(s string) string {
	if len(s) == 0 {
		return strconv.Quote(s)
	}
	for _, r := range s {
		if r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r == '-' || r == '_' {
			continue
		}
		return strconv.Quote(s)
	}
	return s
}
