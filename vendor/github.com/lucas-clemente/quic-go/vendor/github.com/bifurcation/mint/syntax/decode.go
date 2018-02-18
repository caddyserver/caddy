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

// Unmarshaler is the interface implemented by types that can
// unmarshal a TLS description of themselves.  Note that unlike the
// JSON unmarshaler interface, it is not known a priori how much of
// the input data will be consumed.  So the Unmarshaler must state
// how much of the input data it consumed.
type Unmarshaler interface {
	UnmarshalTLS([]byte) (int, error)
}

// These are the options that can be specified in the struct tag.  Right now,
// all of them apply to variable-length vectors and nothing else
type decOpts struct {
	head   uint // length of length in bytes
	min    uint // minimum size in bytes
	max    uint // maximum size in bytes
	varint bool // whether to decode as a varint
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

var (
	unmarshalerType = reflect.TypeOf(new(Unmarshaler)).Elem()
)

func newTypeDecoder(t reflect.Type) decoderFunc {
	if t.Kind() != reflect.Ptr && reflect.PtrTo(t).Implements(unmarshalerType) {
		return unmarshalerDecoder
	}

	switch t.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return uintDecoder
	case reflect.Array:
		return newArrayDecoder(t)
	case reflect.Slice:
		return newSliceDecoder(t)
	case reflect.Struct:
		return newStructDecoder(t)
	case reflect.Ptr:
		return newPointerDecoder(t)
	default:
		panic(fmt.Errorf("Unsupported type (%s)", t))
	}
}

///// Specific decoders below

func unmarshalerDecoder(d *decodeState, v reflect.Value, opts decOpts) int {
	um, ok := v.Interface().(Unmarshaler)
	if !ok {
		panic(fmt.Errorf("Non-Unmarshaler passed to unmarshalerEncoder"))
	}

	read, err := um.UnmarshalTLS(d.Bytes())
	if err != nil {
		panic(err)
	}

	if read > d.Len() {
		panic(fmt.Errorf("Invalid return value from UnmarshalTLS"))
	}

	d.Next(read)
	return read
}

//////////

func uintDecoder(d *decodeState, v reflect.Value, opts decOpts) int {
	if opts.varint {
		return varintDecoder(d, v, opts)
	}

	uintLen := int(v.Elem().Type().Size())
	buf := d.Next(uintLen)
	if len(buf) != uintLen {
		panic(fmt.Errorf("Insufficient data to read uint"))
	}

	return setUintFromBuffer(v, buf)
}

func varintDecoder(d *decodeState, v reflect.Value, opts decOpts) int {
	// Read the first octet and decide the size of the presented varint
	first := d.Next(1)
	if len(first) != 1 {
		panic(fmt.Errorf("Insufficient data to read varint length"))
	}

	uintLen := int(v.Elem().Type().Size())
	twoBits := uint(first[0] >> 6)
	varintLen := 1 << twoBits

	if uintLen < varintLen {
		panic(fmt.Errorf("Uint too small to fit varint: %d < %d"))
	}

	rest := d.Next(varintLen - 1)
	if len(rest) != varintLen-1 {
		panic(fmt.Errorf("Insufficient data to read varint"))
	}

	buf := append(first, rest...)
	buf[0] &= 0x3f
	return setUintFromBuffer(v, buf)
}

func setUintFromBuffer(v reflect.Value, buf []byte) int {
	val := uint64(0)
	for _, b := range buf {
		val = (val << 8) + uint64(b)
	}

	v.Elem().SetUint(val)
	return len(buf)
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

	lengthBytes := d.Next(int(opts.head))
	if len(lengthBytes) != int(opts.head) {
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

	data := d.Next(int(length))
	if len(data) != int(length) {
		panic(fmt.Errorf("Available data less than declared length [%d < %d]", len(data), length))
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
			head:   tagOpts["head"],
			max:    tagOpts["max"],
			min:    tagOpts["min"],
			varint: tagOpts[varintOption] > 0,
		}

		sd.fieldDecs[i] = typeDecoder(f.Type)
	}

	return sd.decode
}

//////////

type pointerDecoder struct {
	base decoderFunc
}

func (pd *pointerDecoder) decode(d *decodeState, v reflect.Value, opts decOpts) int {
	v.Elem().Set(reflect.New(v.Elem().Type().Elem()))
	return pd.base(d, v.Elem(), opts)
}

func newPointerDecoder(t reflect.Type) decoderFunc {
	baseDecoder := typeDecoder(t.Elem())
	pd := pointerDecoder{base: baseDecoder}
	return pd.decode
}
