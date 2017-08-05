package kingpin

//go:generate go run ./cmd/genvalues/main.go

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/alecthomas/units"
)

// NOTE: Most of the base type values were lifted from:
// http://golang.org/src/pkg/flag/flag.go?s=20146:20222

// Value is the interface to the dynamic value stored in a flag.
// (The default value is represented as a string.)
//
// If a Value has an IsBoolFlag() bool method returning true, the command-line
// parser makes --name equivalent to -name=true rather than using the next
// command-line argument, and adds a --no-name counterpart for negating the
// flag.
type Value interface {
	String() string
	Set(string) error
}

// Getter is an interface that allows the contents of a Value to be retrieved.
// It wraps the Value interface, rather than being part of it, because it
// appeared after Go 1 and its compatibility rules. All Value types provided
// by this package satisfy the Getter interface.
type Getter interface {
	Value
	Get() interface{}
}

// Optional interface to indicate boolean flags that don't accept a value, and
// implicitly have a --no-<x> negation counterpart.
type boolFlag interface {
	Value
	IsBoolFlag() bool
}

// Optional interface for arguments that cumulatively consume all remaining
// input.
type remainderArg interface {
	Value
	IsCumulative() bool
}

// Optional interface for flags that can be repeated.
type repeatableFlag interface {
	Value
	IsCumulative() bool
}

type accumulator struct {
	element func(value interface{}) Value
	typ     reflect.Type
	slice   reflect.Value
}

// Use reflection to accumulate values into a slice.
//
// target := []string{}
// newAccumulator(&target, func (value interface{}) Value {
//   return newStringValue(value.(*string))
// })
func newAccumulator(slice interface{}, element func(value interface{}) Value) *accumulator {
	typ := reflect.TypeOf(slice)
	if typ.Kind() != reflect.Ptr || typ.Elem().Kind() != reflect.Slice {
		panic("expected a pointer to a slice")
	}
	return &accumulator{
		element: element,
		typ:     typ.Elem().Elem(),
		slice:   reflect.ValueOf(slice),
	}
}

func (a *accumulator) String() string {
	out := []string{}
	s := a.slice.Elem()
	for i := 0; i < s.Len(); i++ {
		out = append(out, a.element(s.Index(i).Addr().Interface()).String())
	}
	return strings.Join(out, ",")
}

func (a *accumulator) Set(value string) error {
	e := reflect.New(a.typ)
	if err := a.element(e.Interface()).Set(value); err != nil {
		return err
	}
	slice := reflect.Append(a.slice.Elem(), e.Elem())
	a.slice.Elem().Set(slice)
	return nil
}

func (a *accumulator) Get() interface{} {
	return a.slice.Interface()
}

func (a *accumulator) IsCumulative() bool {
	return true
}

func (b *boolValue) IsBoolFlag() bool { return true }

// -- time.Duration Value
type durationValue time.Duration

func newDurationValue(p *time.Duration) *durationValue {
	return (*durationValue)(p)
}

func (d *durationValue) Set(s string) error {
	v, err := time.ParseDuration(s)
	*d = durationValue(v)
	return err
}

func (d *durationValue) Get() interface{} { return time.Duration(*d) }

func (d *durationValue) String() string { return (*time.Duration)(d).String() }

// -- map[string]string Value
type stringMapValue map[string]string

func newStringMapValue(p *map[string]string) *stringMapValue {
	return (*stringMapValue)(p)
}

var stringMapRegex = regexp.MustCompile("[:=]")

func (s *stringMapValue) Set(value string) error {
	parts := stringMapRegex.Split(value, 2)
	if len(parts) != 2 {
		return fmt.Errorf("expected KEY=VALUE got '%s'", value)
	}
	(*s)[parts[0]] = parts[1]
	return nil
}

func (s *stringMapValue) Get() interface{} {
	return (map[string]string)(*s)
}

func (s *stringMapValue) String() string {
	return fmt.Sprintf("%s", map[string]string(*s))
}

func (s *stringMapValue) IsCumulative() bool {
	return true
}

// -- net.IP Value
type ipValue net.IP

func newIPValue(p *net.IP) *ipValue {
	return (*ipValue)(p)
}

func (i *ipValue) Set(value string) error {
	if ip := net.ParseIP(value); ip == nil {
		return fmt.Errorf("'%s' is not an IP address", value)
	} else {
		*i = *(*ipValue)(&ip)
		return nil
	}
}

func (i *ipValue) Get() interface{} {
	return (net.IP)(*i)
}

func (i *ipValue) String() string {
	return (*net.IP)(i).String()
}

// -- *net.TCPAddr Value
type tcpAddrValue struct {
	addr **net.TCPAddr
}

func newTCPAddrValue(p **net.TCPAddr) *tcpAddrValue {
	return &tcpAddrValue{p}
}

func (i *tcpAddrValue) Set(value string) error {
	if addr, err := net.ResolveTCPAddr("tcp", value); err != nil {
		return fmt.Errorf("'%s' is not a valid TCP address: %s", value, err)
	} else {
		*i.addr = addr
		return nil
	}
}

func (t *tcpAddrValue) Get() interface{} {
	return (*net.TCPAddr)(*t.addr)
}

func (i *tcpAddrValue) String() string {
	return (*i.addr).String()
}

// -- existingFile Value

type fileStatValue struct {
	path      *string
	predicate func(os.FileInfo) error
}

func newFileStatValue(p *string, predicate func(os.FileInfo) error) *fileStatValue {
	return &fileStatValue{
		path:      p,
		predicate: predicate,
	}
}

func (e *fileStatValue) Set(value string) error {
	if s, err := os.Stat(value); os.IsNotExist(err) {
		return fmt.Errorf("path '%s' does not exist", value)
	} else if err != nil {
		return err
	} else if err := e.predicate(s); err != nil {
		return err
	}
	*e.path = value
	return nil
}

func (f *fileStatValue) Get() interface{} {
	return (string)(*f.path)
}

func (e *fileStatValue) String() string {
	return *e.path
}

// -- os.File value

type fileValue struct {
	f    **os.File
	flag int
	perm os.FileMode
}

func newFileValue(p **os.File, flag int, perm os.FileMode) *fileValue {
	return &fileValue{p, flag, perm}
}

func (f *fileValue) Set(value string) error {
	if fd, err := os.OpenFile(value, f.flag, f.perm); err != nil {
		return err
	} else {
		*f.f = fd
		return nil
	}
}

func (f *fileValue) Get() interface{} {
	return (*os.File)(*f.f)
}

func (f *fileValue) String() string {
	if *f.f == nil {
		return "<nil>"
	}
	return (*f.f).Name()
}

// -- url.URL Value
type urlValue struct {
	u **url.URL
}

func newURLValue(p **url.URL) *urlValue {
	return &urlValue{p}
}

func (u *urlValue) Set(value string) error {
	if url, err := url.Parse(value); err != nil {
		return fmt.Errorf("invalid URL: %s", err)
	} else {
		*u.u = url
		return nil
	}
}

func (u *urlValue) Get() interface{} {
	return (*url.URL)(*u.u)
}

func (u *urlValue) String() string {
	if *u.u == nil {
		return "<nil>"
	}
	return (*u.u).String()
}

// -- []*url.URL Value
type urlListValue []*url.URL

func newURLListValue(p *[]*url.URL) *urlListValue {
	return (*urlListValue)(p)
}

func (u *urlListValue) Set(value string) error {
	if url, err := url.Parse(value); err != nil {
		return fmt.Errorf("invalid URL: %s", err)
	} else {
		*u = append(*u, url)
		return nil
	}
}

func (u *urlListValue) Get() interface{} {
	return ([]*url.URL)(*u)
}

func (u *urlListValue) String() string {
	out := []string{}
	for _, url := range *u {
		out = append(out, url.String())
	}
	return strings.Join(out, ",")
}

func (u *urlListValue) IsCumulative() bool {
	return true
}

// A flag whose value must be in a set of options.
type enumValue struct {
	value   *string
	options []string
}

func newEnumFlag(target *string, options ...string) *enumValue {
	return &enumValue{
		value:   target,
		options: options,
	}
}

func (a *enumValue) String() string {
	return *a.value
}

func (a *enumValue) Set(value string) error {
	for _, v := range a.options {
		if v == value {
			*a.value = value
			return nil
		}
	}
	return fmt.Errorf("enum value must be one of %s, got '%s'", strings.Join(a.options, ","), value)
}

func (e *enumValue) Get() interface{} {
	return (string)(*e.value)
}

// -- []string Enum Value
type enumsValue struct {
	value   *[]string
	options []string
}

func newEnumsFlag(target *[]string, options ...string) *enumsValue {
	return &enumsValue{
		value:   target,
		options: options,
	}
}

func (s *enumsValue) Set(value string) error {
	for _, v := range s.options {
		if v == value {
			*s.value = append(*s.value, value)
			return nil
		}
	}
	return fmt.Errorf("enum value must be one of %s, got '%s'", strings.Join(s.options, ","), value)
}

func (e *enumsValue) Get() interface{} {
	return ([]string)(*e.value)
}

func (s *enumsValue) String() string {
	return strings.Join(*s.value, ",")
}

func (s *enumsValue) IsCumulative() bool {
	return true
}

// -- units.Base2Bytes Value
type bytesValue units.Base2Bytes

func newBytesValue(p *units.Base2Bytes) *bytesValue {
	return (*bytesValue)(p)
}

func (d *bytesValue) Set(s string) error {
	v, err := units.ParseBase2Bytes(s)
	*d = bytesValue(v)
	return err
}

func (d *bytesValue) Get() interface{} { return units.Base2Bytes(*d) }

func (d *bytesValue) String() string { return (*units.Base2Bytes)(d).String() }

func newExistingFileValue(target *string) *fileStatValue {
	return newFileStatValue(target, func(s os.FileInfo) error {
		if s.IsDir() {
			return fmt.Errorf("'%s' is a directory", s.Name())
		}
		return nil
	})
}

func newExistingDirValue(target *string) *fileStatValue {
	return newFileStatValue(target, func(s os.FileInfo) error {
		if !s.IsDir() {
			return fmt.Errorf("'%s' is a file", s.Name())
		}
		return nil
	})
}

func newExistingFileOrDirValue(target *string) *fileStatValue {
	return newFileStatValue(target, func(s os.FileInfo) error { return nil })
}

type counterValue int

func newCounterValue(n *int) *counterValue {
	return (*counterValue)(n)
}

func (c *counterValue) Set(s string) error {
	*c++
	return nil
}

func (c *counterValue) Get() interface{}   { return (int)(*c) }
func (c *counterValue) IsBoolFlag() bool   { return true }
func (c *counterValue) String() string     { return fmt.Sprintf("%d", *c) }
func (c *counterValue) IsCumulative() bool { return true }

func resolveHost(value string) (net.IP, error) {
	if ip := net.ParseIP(value); ip != nil {
		return ip, nil
	} else {
		if addr, err := net.ResolveIPAddr("ip", value); err != nil {
			return nil, err
		} else {
			return addr.IP, nil
		}
	}
}
