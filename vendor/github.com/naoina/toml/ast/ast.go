package ast

import (
	"strconv"
	"strings"
	"time"
)

type Position struct {
	Begin int
	End   int
}

type Value interface {
	Pos() int
	End() int
	Source() string
}

type String struct {
	Position Position
	Value    string
	Data     []rune
}

func (s *String) Pos() int {
	return s.Position.Begin
}

func (s *String) End() int {
	return s.Position.End
}

func (s *String) Source() string {
	return string(s.Data)
}

type Integer struct {
	Position Position
	Value    string
	Data     []rune
}

func (i *Integer) Pos() int {
	return i.Position.Begin
}

func (i *Integer) End() int {
	return i.Position.End
}

func (i *Integer) Source() string {
	return string(i.Data)
}

func (i *Integer) Int() (int64, error) {
	return strconv.ParseInt(i.Value, 10, 64)
}

type Float struct {
	Position Position
	Value    string
	Data     []rune
}

func (f *Float) Pos() int {
	return f.Position.Begin
}

func (f *Float) End() int {
	return f.Position.End
}

func (f *Float) Source() string {
	return string(f.Data)
}

func (f *Float) Float() (float64, error) {
	return strconv.ParseFloat(f.Value, 64)
}

type Boolean struct {
	Position Position
	Value    string
	Data     []rune
}

func (b *Boolean) Pos() int {
	return b.Position.Begin
}

func (b *Boolean) End() int {
	return b.Position.End
}

func (b *Boolean) Source() string {
	return string(b.Data)
}

func (b *Boolean) Boolean() (bool, error) {
	return strconv.ParseBool(b.Value)
}

type Datetime struct {
	Position Position
	Value    string
	Data     []rune
}

func (d *Datetime) Pos() int {
	return d.Position.Begin
}

func (d *Datetime) End() int {
	return d.Position.End
}

func (d *Datetime) Source() string {
	return string(d.Data)
}

func (d *Datetime) Time() (time.Time, error) {
	switch {
	case !strings.Contains(d.Value, ":"):
		return time.Parse("2006-01-02", d.Value)
	case !strings.Contains(d.Value, "-"):
		return time.Parse("15:04:05.999999999", d.Value)
	default:
		return time.Parse(time.RFC3339Nano, d.Value)
	}
}

type Array struct {
	Position Position
	Value    []Value
	Data     []rune
}

func (a *Array) Pos() int {
	return a.Position.Begin
}

func (a *Array) End() int {
	return a.Position.End
}

func (a *Array) Source() string {
	return string(a.Data)
}

type TableType uint8

const (
	TableTypeNormal TableType = iota
	TableTypeArray
)

var tableTypes = [...]string{
	"normal",
	"array",
}

func (t TableType) String() string {
	return tableTypes[t]
}

type Table struct {
	Position Position
	Line     int
	Name     string
	Fields   map[string]interface{}
	Type     TableType
	Data     []rune
}

func (t *Table) Pos() int {
	return t.Position.Begin
}

func (t *Table) End() int {
	return t.Position.End
}

func (t *Table) Source() string {
	return string(t.Data)
}

type KeyValue struct {
	Key   string
	Value Value
	Line  int
}
