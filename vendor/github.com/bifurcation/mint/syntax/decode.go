package syntax

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
)

func Unmarshal(data []byte, v interface{}) (int, error) {
	// Check for well-formedness.
	// Avoids filling out half a data structure
	// before discovering a JSON syntax error.
	d := decodeState{}
	d.Write(data)
	return d.unmarshal(v)
}

// These are the options that can be specified in the struct tag.  Right now,
// all of them apply to variable-length vectors and nothing else
type decOpts struct {
	head uint // length of length in bytes
	min  uint // minimum size in bytes
	max  uint // maximum size in bytes
}

type decodeState struct {
	bytes.Buffer
}

func (d *decodeState) unmarshal(v interface{}) (read int, err error) {
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

	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return 0, fmt.Errorf("Invalid unmarshal target (non-pointer or nil)")
	}

	read = d.value(rv)
	return read, nil
}

func (e *decodeState) value(v reflect.Value) int {
	return valueDecoder(v)(e, v, decOpts{})
}

type decoderFunc func(e *decodeState, v reflect.Value, opts decOpts) int

func valueDecoder(v reflect.Value) decoderFunc {
	return typeDecoder(v.Type().Elem())
}

func typeDecoder(t reflect.Type) decoderFunc {
	// Note: Omits the caching / wait-group things that encoding/json uses
	return newTypeDecoder(t)
}

func newTypeDecoder(t reflect.Type) decoderFunc {
	// Note: Does not support Marshaler, so don't need the allowAddr argument

	switch t.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return uintDecoder
	case reflect.Array:
		return newArrayDecoder(t)
	case reflect.Slice:
		return newSliceDecoder(t)
	case reflect.Struct:
		return newStructDecoder(t)
	default:
		panic(fmt.Errorf("Unsupported type (%s)", t))
	}
}

///// Specific decoders below

func uintDecoder(d *decodeState, v reflect.Value, opts decOpts) int {
	var uintLen int
	switch v.Elem().Kind() {
	case reflect.Uint8:
		uintLen = 1
	case reflect.Uint16:
		uintLen = 2
	case reflect.Uint32:
		uintLen = 4
	case reflect.Uint64:
		uintLen = 8
	}

	buf := make([]byte, uintLen)
	n, err := d.Read(buf)
	if err != nil {
		panic(err)
	}
	if n != uintLen {
		panic(fmt.Errorf("Insufficient data to read uint"))
	}

	val := uint64(0)
	for _, b := range buf {
		val = (val << 8) + uint64(b)
	}

	v.Elem().SetUint(val)
	return uintLen
}

//////////

type arrayDecoder struct {
	elemDec decoderFunc
}

func (ad *arrayDecoder) decode(d *decodeState, v reflect.Value, opts decOpts) int {
	n := v.Elem().Type().Len()
	read := 0
	for i := 0; i < n; i += 1 {
		read += ad.elemDec(d, v.Elem().Index(i).Addr(), opts)
	}
	return read
}

func newArrayDecoder(t reflect.Type) decoderFunc {
	dec := &arrayDecoder{typeDecoder(t.Elem())}
	return dec.decode
}

//////////

type sliceDecoder struct {
	elementType reflect.Type
	elementDec  decoderFunc
}

func (sd *sliceDecoder) decode(d *decodeState, v reflect.Value, opts decOpts) int {
	if opts.head == 0 {
		panic(fmt.Errorf("Cannot decode a slice without a header length"))
	}

	lengthBytes := make([]byte, opts.head)
	n, err := d.Read(lengthBytes)
	if err != nil {
		panic(err)
	}
	if uint(n) != opts.head {
		panic(fmt.Errorf("Not enough data to read header"))
	}

	length := uint(0)
	for _, b := range lengthBytes {
		length = (length << 8) + uint(b)
	}

	if opts.max > 0 && length > opts.max {
		panic(fmt.Errorf("Length of vector exceeds declared max"))
	}
	if length < opts.min {
		panic(fmt.Errorf("Length of vector below declared min"))
	}

	data := make([]byte, length)
	n, err = d.Read(data)
	if err != nil {
		panic(err)
	}
	if uint(n) != length {
		panic(fmt.Errorf("Available data less than declared length [%04x < %04x]", n, length))
	}

	elemBuf := &decodeState{}
	elemBuf.Write(data)
	elems := []reflect.Value{}
	read := int(opts.head)
	for elemBuf.Len() > 0 {
		elem := reflect.New(sd.elementType)
		read += sd.elementDec(elemBuf, elem, opts)
		elems = append(elems, elem)
	}

	v.Elem().Set(reflect.MakeSlice(v.Elem().Type(), len(elems), len(elems)))
	for i := 0; i < len(elems); i += 1 {
		v.Elem().Index(i).Set(elems[i].Elem())
	}
	return read
}

func newSliceDecoder(t reflect.Type) decoderFunc {
	dec := &sliceDecoder{
		elementType: t.Elem(),
		elementDec:  typeDecoder(t.Elem()),
	}
	return dec.decode
}

//////////

type structDecoder struct {
	fieldOpts []decOpts
	fieldDecs []decoderFunc
}

func (sd *structDecoder) decode(d *decodeState, v reflect.Value, opts decOpts) int {
	read := 0
	for i := range sd.fieldDecs {
		read += sd.fieldDecs[i](d, v.Elem().Field(i).Addr(), sd.fieldOpts[i])
	}
	return read
}

func newStructDecoder(t reflect.Type) decoderFunc {
	n := t.NumField()
	sd := structDecoder{
		fieldOpts: make([]decOpts, n),
		fieldDecs: make([]decoderFunc, n),
	}

	for i := 0; i < n; i += 1 {
		f := t.Field(i)

		tag := f.Tag.Get("tls")
		tagOpts := parseTag(tag)

		sd.fieldOpts[i] = decOpts{
			head: tagOpts["head"],
			max:  tagOpts["max"],
			min:  tagOpts["min"],
		}

		sd.fieldDecs[i] = typeDecoder(f.Type)
	}

	return sd.decode
}
