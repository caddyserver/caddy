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

// Marshaler is the interface implemented by types that
// have a defined TLS encoding.
type Marshaler interface {
	MarshalTLS() ([]byte, error)
}

// These are the options that can be specified in the struct tag.  Right now,
// all of them apply to variable-length vectors and nothing else
type encOpts struct {
	head   uint // length of length in bytes
	min    uint // minimum size in bytes
	max    uint // maximum size in bytes
	varint bool // whether to encode as a varint
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

var (
	marshalerType = reflect.TypeOf(new(Marshaler)).Elem()
)

func newTypeEncoder(t reflect.Type) encoderFunc {
	if t.Implements(marshalerType) {
		return marshalerEncoder
	}

	switch t.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return uintEncoder
	case reflect.Array:
		return newArrayEncoder(t)
	case reflect.Slice:
		return newSliceEncoder(t)
	case reflect.Struct:
		return newStructEncoder(t)
	case reflect.Ptr:
		return newPointerEncoder(t)
	default:
		panic(fmt.Errorf("Unsupported type (%s)", t))
	}
}

///// Specific encoders below

func marshalerEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	if v.Kind() == reflect.Ptr && v.IsNil() {
		panic(fmt.Errorf("Cannot encode nil pointer"))
	}

	m, ok := v.Interface().(Marshaler)
	if !ok {
		panic(fmt.Errorf("Non-Marshaler passed to marshalerEncoder"))
	}

	b, err := m.MarshalTLS()
	if err == nil {
		_, err = e.Write(b)
	}

	if err != nil {
		panic(err)
	}
}

//////////

func uintEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	if opts.varint {
		varintEncoder(e, v, opts)
		return
	}

	writeUint(e, v.Uint(), int(v.Type().Size()))
}

func varintEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	u := v.Uint()
	if (u >> 62) > 0 {
		panic(fmt.Errorf("uint value is too big for varint"))
	}

	var varintLen int
	for _, len := range []uint{1, 2, 4, 8} {
		if u < (uint64(1) << (8*len - 2)) {
			varintLen = int(len)
			break
		}
	}

	twoBits := map[int]uint64{1: 0x00, 2: 0x01, 4: 0x02, 8: 0x03}[varintLen]
	shift := uint(8*varintLen - 2)
	writeUint(e, u|(twoBits<<shift), varintLen)
}

func writeUint(e *encodeState, u uint64, len int) {
	data := make([]byte, len)
	for i := 0; i < len; i += 1 {
		data[i] = byte(u >> uint(8*(len-i-1)))
	}
	e.Write(data)
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
			head:   tagOpts["head"],
			max:    tagOpts["max"],
			min:    tagOpts["min"],
			varint: tagOpts[varintOption] > 0,
		}
		se.fieldEncs[i] = typeEncoder(f.Type)
	}

	return se.encode
}

//////////

type pointerEncoder struct {
	base encoderFunc
}

func (pe pointerEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		panic(fmt.Errorf("Cannot marshal a struct containing a nil pointer"))
	}

	pe.base(e, v.Elem(), opts)
}

func newPointerEncoder(t reflect.Type) encoderFunc {
	baseEncoder := typeEncoder(t.Elem())
	pe := pointerEncoder{base: baseEncoder}
	return pe.encode
}
