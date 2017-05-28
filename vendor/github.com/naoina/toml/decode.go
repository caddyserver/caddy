// Package toml encodes and decodes the TOML configuration format using reflection.
//
// This library is compatible with TOML version v0.4.0.
package toml

import (
	"encoding"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/naoina/toml/ast"
)

const (
	tableSeparator = '.'
)

var (
	escapeReplacer = strings.NewReplacer(
		"\b", "\\n",
		"\f", "\\f",
		"\n", "\\n",
		"\r", "\\r",
		"\t", "\\t",
	)
	underscoreReplacer = strings.NewReplacer(
		"_", "",
	)
)

var timeType = reflect.TypeOf(time.Time{})

// Unmarshal parses the TOML data and stores the result in the value pointed to by v.
//
// Unmarshal will mapped to v that according to following rules:
//
//	TOML strings to string
//	TOML integers to any int type
//	TOML floats to float32 or float64
//	TOML booleans to bool
//	TOML datetimes to time.Time
//	TOML arrays to any type of slice
//	TOML tables to struct or map
//	TOML array tables to slice of struct or map
func (cfg *Config) Unmarshal(data []byte, v interface{}) error {
	table, err := Parse(data)
	if err != nil {
		return err
	}
	if err := cfg.UnmarshalTable(table, v); err != nil {
		return err
	}
	return nil
}

// A Decoder reads and decodes TOML from an input stream.
type Decoder struct {
	r   io.Reader
	cfg *Config
}

// NewDecoder returns a new Decoder that reads from r.
// Note that it reads all from r before parsing it.
func (cfg *Config) NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r, cfg}
}

// Decode parses the TOML data from its input and stores it in the value pointed to by v.
// See the documentation for Unmarshal for details about the conversion of TOML into a Go value.
func (d *Decoder) Decode(v interface{}) error {
	b, err := ioutil.ReadAll(d.r)
	if err != nil {
		return err
	}
	return d.cfg.Unmarshal(b, v)
}

// UnmarshalerRec may be implemented by types to customize their behavior when being
// unmarshaled from TOML. You can use it to implement custom validation or to set
// unexported fields.
//
// UnmarshalTOML receives a function that can be called to unmarshal the original TOML
// value into a field or variable. It is safe to call the function more than once if
// necessary.
type UnmarshalerRec interface {
	UnmarshalTOML(fn func(interface{}) error) error
}

// Unmarshaler can be used to capture and process raw TOML source of a table or value.
// UnmarshalTOML must copy the input if it wishes to retain it after returning.
//
// Note: this interface is retained for backwards compatibility. You probably want
// to implement encoding.TextUnmarshaler or UnmarshalerRec instead.
type Unmarshaler interface {
	UnmarshalTOML(input []byte) error
}

// UnmarshalTable applies the contents of an ast.Table to the value pointed at by v.
//
// UnmarshalTable will mapped to v that according to following rules:
//
//	TOML strings to string
//	TOML integers to any int type
//	TOML floats to float32 or float64
//	TOML booleans to bool
//	TOML datetimes to time.Time
//	TOML arrays to any type of slice
//	TOML tables to struct or map
//	TOML array tables to slice of struct or map
func (cfg *Config) UnmarshalTable(t *ast.Table, v interface{}) error {
	rv := reflect.ValueOf(v)
	toplevelMap := rv.Kind() == reflect.Map
	if (!toplevelMap && rv.Kind() != reflect.Ptr) || rv.IsNil() {
		return &invalidUnmarshalError{reflect.TypeOf(v)}
	}
	return unmarshalTable(cfg, rv, t, toplevelMap)
}

// used for UnmarshalerRec.
func unmarshalTableOrValue(cfg *Config, rv reflect.Value, av interface{}) error {
	if (rv.Kind() != reflect.Ptr && rv.Kind() != reflect.Map) || rv.IsNil() {
		return &invalidUnmarshalError{rv.Type()}
	}
	rv = indirect(rv)

	switch av.(type) {
	case *ast.KeyValue, *ast.Table, []*ast.Table:
		if err := unmarshalField(cfg, rv, av); err != nil {
			return lineError(fieldLineNumber(av), err)
		}
		return nil
	case ast.Value:
		return setValue(cfg, rv, av.(ast.Value))
	default:
		panic(fmt.Sprintf("BUG: unhandled AST node type %T", av))
	}
}

// unmarshalTable unmarshals the fields of a table into a struct or map.
//
// toplevelMap is true when rv is an (unadressable) map given to UnmarshalTable. In this
// (special) case, the map is used as-is instead of creating a new map.
func unmarshalTable(cfg *Config, rv reflect.Value, t *ast.Table, toplevelMap bool) error {
	rv = indirect(rv)
	if err, ok := setUnmarshaler(cfg, rv, t); ok {
		return lineError(t.Line, err)
	}
	switch {
	case rv.Kind() == reflect.Struct:
		fc := makeFieldCache(cfg, rv.Type())
		for key, fieldAst := range t.Fields {
			fv, fieldName, err := fc.findField(cfg, rv, key)
			if err != nil {
				return lineError(fieldLineNumber(fieldAst), err)
			}
			if fv.IsValid() {
				if err := unmarshalField(cfg, fv, fieldAst); err != nil {
					return lineErrorField(fieldLineNumber(fieldAst), rv.Type().String()+"."+fieldName, err)
				}
			}
		}
	case rv.Kind() == reflect.Map || isEface(rv):
		m := rv
		if !toplevelMap {
			if rv.Kind() == reflect.Interface {
				m = reflect.ValueOf(make(map[string]interface{}))
			} else {
				m = reflect.MakeMap(rv.Type())
			}
		}
		elemtyp := m.Type().Elem()
		for key, fieldAst := range t.Fields {
			kv, err := unmarshalMapKey(m.Type().Key(), key)
			if err != nil {
				return lineError(fieldLineNumber(fieldAst), err)
			}
			fv := reflect.New(elemtyp).Elem()
			if err := unmarshalField(cfg, fv, fieldAst); err != nil {
				return lineError(fieldLineNumber(fieldAst), err)
			}
			m.SetMapIndex(kv, fv)
		}
		if !toplevelMap {
			rv.Set(m)
		}
	default:
		return lineError(t.Line, &unmarshalTypeError{"table", "struct or map", rv.Type()})
	}
	return nil
}

func fieldLineNumber(fieldAst interface{}) int {
	switch av := fieldAst.(type) {
	case *ast.KeyValue:
		return av.Line
	case *ast.Table:
		return av.Line
	case []*ast.Table:
		return av[0].Line
	default:
		panic(fmt.Sprintf("BUG: unhandled node type %T", fieldAst))
	}
}

func unmarshalField(cfg *Config, rv reflect.Value, fieldAst interface{}) error {
	switch av := fieldAst.(type) {
	case *ast.KeyValue:
		return setValue(cfg, rv, av.Value)
	case *ast.Table:
		return unmarshalTable(cfg, rv, av, false)
	case []*ast.Table:
		rv = indirect(rv)
		if err, ok := setUnmarshaler(cfg, rv, fieldAst); ok {
			return err
		}
		var slice reflect.Value
		switch {
		case rv.Kind() == reflect.Slice:
			slice = reflect.MakeSlice(rv.Type(), len(av), len(av))
		case isEface(rv):
			slice = reflect.ValueOf(make([]interface{}, len(av)))
		default:
			return &unmarshalTypeError{"array table", "slice", rv.Type()}
		}
		for i, tbl := range av {
			vv := reflect.New(slice.Type().Elem()).Elem()
			if err := unmarshalTable(cfg, vv, tbl, false); err != nil {
				return err
			}
			slice.Index(i).Set(vv)
		}
		rv.Set(slice)
	default:
		panic(fmt.Sprintf("BUG: unhandled AST node type %T", av))
	}
	return nil
}

func unmarshalMapKey(typ reflect.Type, key string) (reflect.Value, error) {
	rv := reflect.New(typ).Elem()
	if u, ok := rv.Addr().Interface().(encoding.TextUnmarshaler); ok {
		return rv, u.UnmarshalText([]byte(key))
	}
	switch typ.Kind() {
	case reflect.String:
		rv.SetString(key)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := strconv.ParseInt(key, 10, int(typ.Size()*8))
		if err != nil {
			return rv, convertNumError(typ.Kind(), err)
		}
		rv.SetInt(i)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		i, err := strconv.ParseUint(key, 10, int(typ.Size()*8))
		if err != nil {
			return rv, convertNumError(typ.Kind(), err)
		}
		rv.SetUint(i)
	default:
		return rv, fmt.Errorf("invalid map key type %s", typ)
	}
	return rv, nil
}

func setValue(cfg *Config, lhs reflect.Value, val ast.Value) error {
	lhs = indirect(lhs)
	if err, ok := setUnmarshaler(cfg, lhs, val); ok {
		return err
	}
	if err, ok := setTextUnmarshaler(lhs, val); ok {
		return err
	}
	switch v := val.(type) {
	case *ast.Integer:
		return setInt(lhs, v)
	case *ast.Float:
		return setFloat(lhs, v)
	case *ast.String:
		return setString(lhs, v)
	case *ast.Boolean:
		return setBoolean(lhs, v)
	case *ast.Datetime:
		return setDatetime(lhs, v)
	case *ast.Array:
		return setArray(cfg, lhs, v)
	default:
		panic(fmt.Sprintf("BUG: unhandled node type %T", v))
	}
}

func indirect(rv reflect.Value) reflect.Value {
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			rv.Set(reflect.New(rv.Type().Elem()))
		}
		rv = rv.Elem()
	}
	return rv
}

func setUnmarshaler(cfg *Config, lhs reflect.Value, av interface{}) (error, bool) {
	if lhs.CanAddr() {
		if u, ok := lhs.Addr().Interface().(UnmarshalerRec); ok {
			err := u.UnmarshalTOML(func(v interface{}) error {
				return unmarshalTableOrValue(cfg, reflect.ValueOf(v), av)
			})
			return err, true
		}
		if u, ok := lhs.Addr().Interface().(Unmarshaler); ok {
			return u.UnmarshalTOML(unmarshalerSource(av)), true
		}
	}
	return nil, false
}

func unmarshalerSource(av interface{}) []byte {
	var source []byte
	switch av := av.(type) {
	case []*ast.Table:
		for i, tab := range av {
			source = append(source, tab.Source()...)
			if i != len(av)-1 {
				source = append(source, '\n')
			}
		}
	case ast.Value:
		source = []byte(av.Source())
	default:
		panic(fmt.Sprintf("BUG: unhandled node type %T", av))
	}
	return source
}

func setTextUnmarshaler(lhs reflect.Value, val ast.Value) (error, bool) {
	if !lhs.CanAddr() {
		return nil, false
	}
	u, ok := lhs.Addr().Interface().(encoding.TextUnmarshaler)
	if !ok || lhs.Type() == timeType {
		return nil, false
	}
	var data string
	switch val := val.(type) {
	case *ast.Array:
		return &unmarshalTypeError{"array", "", lhs.Type()}, true
	case *ast.String:
		data = val.Value
	default:
		data = val.Source()
	}
	return u.UnmarshalText([]byte(data)), true
}

func setInt(fv reflect.Value, v *ast.Integer) error {
	k := fv.Kind()
	switch {
	case k >= reflect.Int && k <= reflect.Int64:
		i, err := strconv.ParseInt(v.Value, 10, int(fv.Type().Size()*8))
		if err != nil {
			return convertNumError(fv.Kind(), err)
		}
		fv.SetInt(i)
	case k >= reflect.Uint && k <= reflect.Uintptr:
		i, err := strconv.ParseUint(v.Value, 10, int(fv.Type().Size()*8))
		if err != nil {
			return convertNumError(fv.Kind(), err)
		}
		fv.SetUint(i)
	case isEface(fv):
		i, err := strconv.ParseInt(v.Value, 10, 64)
		if err != nil {
			return convertNumError(reflect.Int64, err)
		}
		fv.Set(reflect.ValueOf(i))
	default:
		return &unmarshalTypeError{"integer", "", fv.Type()}
	}
	return nil
}

func setFloat(fv reflect.Value, v *ast.Float) error {
	f, err := v.Float()
	if err != nil {
		return err
	}
	switch {
	case fv.Kind() == reflect.Float32 || fv.Kind() == reflect.Float64:
		if fv.OverflowFloat(f) {
			return &overflowError{fv.Kind(), v.Value}
		}
		fv.SetFloat(f)
	case isEface(fv):
		fv.Set(reflect.ValueOf(f))
	default:
		return &unmarshalTypeError{"float", "", fv.Type()}
	}
	return nil
}

func setString(fv reflect.Value, v *ast.String) error {
	switch {
	case fv.Kind() == reflect.String:
		fv.SetString(v.Value)
	case isEface(fv):
		fv.Set(reflect.ValueOf(v.Value))
	default:
		return &unmarshalTypeError{"string", "", fv.Type()}
	}
	return nil
}

func setBoolean(fv reflect.Value, v *ast.Boolean) error {
	b, _ := v.Boolean()
	switch {
	case fv.Kind() == reflect.Bool:
		fv.SetBool(b)
	case isEface(fv):
		fv.Set(reflect.ValueOf(b))
	default:
		return &unmarshalTypeError{"boolean", "", fv.Type()}
	}
	return nil
}

func setDatetime(rv reflect.Value, v *ast.Datetime) error {
	t, err := v.Time()
	if err != nil {
		return err
	}
	if !timeType.AssignableTo(rv.Type()) {
		return &unmarshalTypeError{"datetime", "", rv.Type()}
	}
	rv.Set(reflect.ValueOf(t))
	return nil
}

func setArray(cfg *Config, rv reflect.Value, v *ast.Array) error {
	var slicetyp reflect.Type
	switch {
	case rv.Kind() == reflect.Slice:
		slicetyp = rv.Type()
	case isEface(rv):
		slicetyp = reflect.SliceOf(rv.Type())
	default:
		return &unmarshalTypeError{"array", "slice", rv.Type()}
	}

	if len(v.Value) == 0 {
		// Ensure defined slices are always set to a non-nil value.
		rv.Set(reflect.MakeSlice(slicetyp, 0, 0))
		return nil
	}

	tomltyp := reflect.TypeOf(v.Value[0])
	slice := reflect.MakeSlice(slicetyp, len(v.Value), len(v.Value))
	typ := slicetyp.Elem()
	for i, vv := range v.Value {
		if i > 0 && tomltyp != reflect.TypeOf(vv) {
			return errArrayMultiType
		}
		tmp := reflect.New(typ).Elem()
		if err := setValue(cfg, tmp, vv); err != nil {
			return err
		}
		slice.Index(i).Set(tmp)
	}
	rv.Set(slice)
	return nil
}

func isEface(rv reflect.Value) bool {
	return rv.Kind() == reflect.Interface && rv.Type().NumMethod() == 0
}
