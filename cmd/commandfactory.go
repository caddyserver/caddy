package caddycmd

import (
	"github.com/spf13/cobra"
)

type RootCommandFactory struct {
	constructor func() *cobra.Command
	options     []func(*cobra.Command)
}

func NewRootCommandFactory(fn func() *cobra.Command) *RootCommandFactory {
	return &RootCommandFactory{
		constructor: fn,
	}
}

func (f *RootCommandFactory) Use(fn func(cmd *cobra.Command)) {
	f.options = append(f.options, fn)
}

func (f *RootCommandFactory) Build() *cobra.Command {
	o := f.constructor()
	for _, v := range f.options {
		v(o)
	}
	return o
}
