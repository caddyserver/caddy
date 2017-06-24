package kingpin

import (
	"fmt"
)

type argGroup struct {
	args []*ArgClause
}

func newArgGroup() *argGroup {
	return &argGroup{}
}

func (a *argGroup) have() bool {
	return len(a.args) > 0
}

// GetArg gets an argument definition.
//
// This allows existing arguments to be modified after definition but before parsing. Useful for
// modular applications.
func (a *argGroup) GetArg(name string) *ArgClause {
	for _, arg := range a.args {
		if arg.name == name {
			return arg
		}
	}
	return nil
}

func (a *argGroup) Arg(name, help string) *ArgClause {
	arg := newArg(name, help)
	a.args = append(a.args, arg)
	return arg
}

func (a *argGroup) init() error {
	required := 0
	seen := map[string]struct{}{}
	previousArgMustBeLast := false
	for i, arg := range a.args {
		if previousArgMustBeLast {
			return fmt.Errorf("Args() can't be followed by another argument '%s'", arg.name)
		}
		if arg.consumesRemainder() {
			previousArgMustBeLast = true
		}
		if _, ok := seen[arg.name]; ok {
			return fmt.Errorf("duplicate argument '%s'", arg.name)
		}
		seen[arg.name] = struct{}{}
		if arg.required && required != i {
			return fmt.Errorf("required arguments found after non-required")
		}
		if arg.required {
			required++
		}
		if err := arg.init(); err != nil {
			return err
		}
	}
	return nil
}

type ArgClause struct {
	actionMixin
	parserMixin
	completionsMixin
	envarMixin
	name          string
	help          string
	defaultValues []string
	required      bool
}

func newArg(name, help string) *ArgClause {
	a := &ArgClause{
		name: name,
		help: help,
	}
	return a
}

func (a *ArgClause) setDefault() error {
	if a.HasEnvarValue() {
		if v, ok := a.value.(remainderArg); !ok || !v.IsCumulative() {
			// Use the value as-is
			return a.value.Set(a.GetEnvarValue())
		}
		for _, value := range a.GetSplitEnvarValue() {
			if err := a.value.Set(value); err != nil {
				return err
			}
		}
		return nil
	}

	if len(a.defaultValues) > 0 {
		for _, defaultValue := range a.defaultValues {
			if err := a.value.Set(defaultValue); err != nil {
				return err
			}
		}
		return nil
	}

	return nil
}

func (a *ArgClause) needsValue() bool {
	haveDefault := len(a.defaultValues) > 0
	return a.required && !(haveDefault || a.HasEnvarValue())
}

func (a *ArgClause) consumesRemainder() bool {
	if r, ok := a.value.(remainderArg); ok {
		return r.IsCumulative()
	}
	return false
}

// Required arguments must be input by the user. They can not have a Default() value provided.
func (a *ArgClause) Required() *ArgClause {
	a.required = true
	return a
}

// Default values for this argument. They *must* be parseable by the value of the argument.
func (a *ArgClause) Default(values ...string) *ArgClause {
	a.defaultValues = values
	return a
}

// Envar overrides the default value(s) for a flag from an environment variable,
// if it is set. Several default values can be provided by using new lines to
// separate them.
func (a *ArgClause) Envar(name string) *ArgClause {
	a.envar = name
	a.noEnvar = false
	return a
}

// NoEnvar forces environment variable defaults to be disabled for this flag.
// Most useful in conjunction with app.DefaultEnvars().
func (a *ArgClause) NoEnvar() *ArgClause {
	a.envar = ""
	a.noEnvar = true
	return a
}

func (a *ArgClause) Action(action Action) *ArgClause {
	a.addAction(action)
	return a
}

func (a *ArgClause) PreAction(action Action) *ArgClause {
	a.addPreAction(action)
	return a
}

// HintAction registers a HintAction (function) for the arg to provide completions
func (a *ArgClause) HintAction(action HintAction) *ArgClause {
	a.addHintAction(action)
	return a
}

// HintOptions registers any number of options for the flag to provide completions
func (a *ArgClause) HintOptions(options ...string) *ArgClause {
	a.addHintAction(func() []string {
		return options
	})
	return a
}

func (a *ArgClause) init() error {
	if a.required && len(a.defaultValues) > 0 {
		return fmt.Errorf("required argument '%s' with unusable default value", a.name)
	}
	if a.value == nil {
		return fmt.Errorf("no parser defined for arg '%s'", a.name)
	}
	return nil
}
