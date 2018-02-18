package syntax

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
)

func Marshal(v interface{}) ([]byte, error) {
	e := &encodeState{}
	err := e.marshal(v, encOpts{})
	if err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// These are the options that can be specified in the struct tag.  Right now,
// all of them apply to variable-length vectors and nothing else
type encOpts struct {
	head uint // length of length in bytes
	min  uint // minimum size in bytes
	max  uint // maximum size in bytes
}

type encodeState struct {
	bytes.Buffer
}

func (e *encodeState) marshal(v interface{}, opts encOpts) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			if s, ok := r.(string); ok {
				panic(s)
			}
			err = r.(error)
		}
	}()
	e.reflectValue(reflect.ValueOf(v), opts)
	return nil
}

func (e *encodeState) reflectValue(v reflect.Value, opts encOpts) {
	valueEncoder(v)(e, v, opts)
}

type encoderFunc func(e *encodeState, v reflect.Value, opts encOpts)

func valueEncoder(v reflect.Value) encoderFunc {
	if !v.IsValid() {
		panic(fmt.Errorf("Cannot encode an invalid value"))
	}
	return typeEncoder(v.Type())
}

func typeEncoder(t reflect.Type) encoderFunc {
	// Note: Omits the caching / wait-group things that encoding/json uses
	return newTypeEncoder(t)
}

func newTypeEncoder(t reflect.Type) encoderFunc {
	// Note: Does not support Marshaler, so don't need the allowAddr argument

	switch t.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return uintEncoder
	case reflect.Array:
		return newArrayEncoder(t)
	case reflect.Slice:
		return newSliceEncoder(t)
	case reflect.Struct:
		return newStructEncoder(t)
	default:
		panic(fmt.Errorf("Unsupported type (%s)", t))
	}
}

///// Specific encoders below

func uintEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	u := v.Uint()
	switch v.Type().Kind() {
	case reflect.Uint8:
		e.WriteByte(byte(u))
	case reflect.Uint16:
		e.Write([]byte{byte(u >> 8), byte(u)})
	case reflect.Uint32:
		e.Write([]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
	case reflect.Uint64:
		e.Write([]byte{byte(u >> 56), byte(u >> 48), byte(u >> 40), byte(u >> 32),
			byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
	}
}

//////////

type arrayEncoder struct {
	elemEnc encoderFunc
}

func (ae *arrayEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	n := v.Len()
	for i := 0; i < n; i += 1 {
		ae.elemEnc(e, v.Index(i), opts)
	}
}

func newArrayEncoder(t reflect.Type) encoderFunc {
	enc := &arrayEncoder{typeEncoder(t.Elem())}
	return enc.encode
}

//////////

type sliceEncoder struct {
	ae *arrayEncoder
}

func (se *sliceEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if opts.head == 0 {
		panic(fmt.Errorf("Cannot encode a slice without a header length"))
	}

	arrayState := &encodeState{}
	se.ae.encode(arrayState, v, opts)

	n := uint(arrayState.Len())
	if opts.max > 0 && n > opts.max {
		panic(fmt.Errorf("Encoded length more than max [%d > %d]", n, opts.max))
	}
	if n>>(8*opts.head) > 0 {
		panic(fmt.Errorf("Encoded length too long for header length [%d, %d]", n, opts.head))
	}
	if n < opts.min {
		panic(fmt.Errorf("Encoded length less than min [%d < %d]", n, opts.min))
	}

	for i := int(opts.head - 1); i >= 0; i -= 1 {
		e.WriteByte(byte(n >> (8 * uint(i))))
	}
	e.Write(arrayState.Bytes())
}

func newSliceEncoder(t reflect.Type) encoderFunc {
	enc := &sliceEncoder{&arrayEncoder{typeEncoder(t.Elem())}}
	return enc.encode
}

//////////

type structEncoder struct {
	fieldOpts []encOpts
	fieldEncs []encoderFunc
}

func (se *structEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	for i := range se.fieldEncs {
		se.fieldEncs[i](e, v.Field(i), se.fieldOpts[i])
	}
}

func newStructEncoder(t reflect.Type) encoderFunc {
	n := t.NumField()
	se := structEncoder{
		fieldOpts: make([]encOpts, n),
		fieldEncs: make([]encoderFunc, n),
	}

	for i := 0; i < n; i += 1 {
		f := t.Field(i)
		tag := f.Tag.Get("tls")
		tagOpts := parseTag(tag)

		se.fieldOpts[i] = encOpts{
			head: tagOpts["head"],
			max:  tagOpts["max"],
			min:  tagOpts["min"],
		}
		se.fieldEncs[i] = typeEncoder(f.Type)
	}

	return se.encode
}
