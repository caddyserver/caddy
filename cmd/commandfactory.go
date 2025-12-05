package caddycmd

import (
	"github.com/spf13/cobra"
)

type rootCommandFactory struct {
	constructor func() *cobra.Command
	options     []func(*cobra.Command)
}

func newRootCommandFactory(fn func() *cobra.Command) *rootCommandFactory {
	return &rootCommandFactory{
		constructor: fn,
	}
}

func (f *rootCommandFactory) Use(fn func(cmd *cobra.Command)) {
	f.options = append(f.options, fn)
}

func (f *rootCommandFactory) Build() *cobra.Command {
	o := f.constructor()
	for _, v := range f.options {
		v(o)
	}
	return o
}
