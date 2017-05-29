package kingpin

import (
	"fmt"
	"strings"
)

type flagGroup struct {
	short     map[string]*FlagClause
	long      map[string]*FlagClause
	flagOrder []*FlagClause
}

func newFlagGroup() *flagGroup {
	return &flagGroup{
		short: map[string]*FlagClause{},
		long:  map[string]*FlagClause{},
	}
}

// GetFlag gets a flag definition.
//
// This allows existing flags to be modified after definition but before parsing. Useful for
// modular applications.
func (f *flagGroup) GetFlag(name string) *FlagClause {
	return f.long[name]
}

// Flag defines a new flag with the given long name and help.
func (f *flagGroup) Flag(name, help string) *FlagClause {
	flag := newFlag(name, help)
	f.long[name] = flag
	f.flagOrder = append(f.flagOrder, flag)
	return flag
}

func (f *flagGroup) init(defaultEnvarPrefix string) error {
	if err := f.checkDuplicates(); err != nil {
		return err
	}
	for _, flag := range f.long {
		if defaultEnvarPrefix != "" && !flag.noEnvar && flag.envar == "" {
			flag.envar = envarTransform(defaultEnvarPrefix + "_" + flag.name)
		}
		if err := flag.init(); err != nil {
			return err
		}
		if flag.shorthand != 0 {
			f.short[string(flag.shorthand)] = flag
		}
	}
	return nil
}

func (f *flagGroup) checkDuplicates() error {
	seenShort := map[rune]bool{}
	seenLong := map[string]bool{}
	for _, flag := range f.flagOrder {
		if flag.shorthand != 0 {
			if _, ok := seenShort[flag.shorthand]; ok {
				return fmt.Errorf("duplicate short flag -%c", flag.shorthand)
			}
			seenShort[flag.shorthand] = true
		}
		if _, ok := seenLong[flag.name]; ok {
			return fmt.Errorf("duplicate long flag --%s", flag.name)
		}
		seenLong[flag.name] = true
	}
	return nil
}

func (f *flagGroup) parse(context *ParseContext) (*FlagClause, error) {
	var token *Token

loop:
	for {
		token = context.Peek()
		switch token.Type {
		case TokenEOL:
			break loop

		case TokenLong, TokenShort:
			flagToken := token
			defaultValue := ""
			var flag *FlagClause
			var ok bool
			invert := false

			name := token.Value
			if token.Type == TokenLong {
				flag, ok = f.long[name]
				if !ok {
					if strings.HasPrefix(name, "no-") {
						name = name[3:]
						invert = true
					}
					flag, ok = f.long[name]
				}
				if !ok {
					return nil, fmt.Errorf("unknown long flag '%s'", flagToken)
				}
			} else {
				flag, ok = f.short[name]
				if !ok {
					return nil, fmt.Errorf("unknown short flag '%s'", flagToken)
				}
			}

			context.Next()

			fb, ok := flag.value.(boolFlag)
			if ok && fb.IsBoolFlag() {
				if invert {
					defaultValue = "false"
				} else {
					defaultValue = "true"
				}
			} else {
				if invert {
					context.Push(token)
					return nil, fmt.Errorf("unknown long flag '%s'", flagToken)
				}
				token = context.Peek()
				if token.Type != TokenArg {
					context.Push(token)
					return nil, fmt.Errorf("expected argument for flag '%s'", flagToken)
				}
				context.Next()
				defaultValue = token.Value
			}

			context.matchedFlag(flag, defaultValue)
			return flag, nil

		default:
			break loop
		}
	}
	return nil, nil
}

// FlagClause is a fluid interface used to build flags.
type FlagClause struct {
	parserMixin
	actionMixin
	completionsMixin
	envarMixin
	name          string
	shorthand     rune
	help          string
	defaultValues []string
	placeholder   string
	hidden        bool
}

func newFlag(name, help string) *FlagClause {
	f := &FlagClause{
		name: name,
		help: help,
	}
	return f
}

func (f *FlagClause) setDefault() error {
	if f.HasEnvarValue() {
		if v, ok := f.value.(repeatableFlag); !ok || !v.IsCumulative() {
			// Use the value as-is
			return f.value.Set(f.GetEnvarValue())
		} else {
			for _, value := range f.GetSplitEnvarValue() {
				if err := f.value.Set(value); err != nil {
					return err
				}
			}
			return nil
		}
	}

	if len(f.defaultValues) > 0 {
		for _, defaultValue := range f.defaultValues {
			if err := f.value.Set(defaultValue); err != nil {
				return err
			}
		}
		return nil
	}

	return nil
}

func (f *FlagClause) needsValue() bool {
	haveDefault := len(f.defaultValues) > 0
	return f.required && !(haveDefault || f.HasEnvarValue())
}

func (f *FlagClause) init() error {
	if f.required && len(f.defaultValues) > 0 {
		return fmt.Errorf("required flag '--%s' with default value that will never be used", f.name)
	}
	if f.value == nil {
		return fmt.Errorf("no type defined for --%s (eg. .String())", f.name)
	}
	if v, ok := f.value.(repeatableFlag); (!ok || !v.IsCumulative()) && len(f.defaultValues) > 1 {
		return fmt.Errorf("invalid default for '--%s', expecting single value", f.name)
	}
	return nil
}

// Dispatch to the given function after the flag is parsed and validated.
func (f *FlagClause) Action(action Action) *FlagClause {
	f.addAction(action)
	return f
}

func (f *FlagClause) PreAction(action Action) *FlagClause {
	f.addPreAction(action)
	return f
}

// HintAction registers a HintAction (function) for the flag to provide completions
func (a *FlagClause) HintAction(action HintAction) *FlagClause {
	a.addHintAction(action)
	return a
}

// HintOptions registers any number of options for the flag to provide completions
func (a *FlagClause) HintOptions(options ...string) *FlagClause {
	a.addHintAction(func() []string {
		return options
	})
	return a
}

func (a *FlagClause) EnumVar(target *string, options ...string) {
	a.parserMixin.EnumVar(target, options...)
	a.addHintActionBuiltin(func() []string {
		return options
	})
}

func (a *FlagClause) Enum(options ...string) (target *string) {
	a.addHintActionBuiltin(func() []string {
		return options
	})
	return a.parserMixin.Enum(options...)
}

// Default values for this flag. They *must* be parseable by the value of the flag.
func (f *FlagClause) Default(values ...string) *FlagClause {
	f.defaultValues = values
	return f
}

// DEPRECATED: Use Envar(name) instead.
func (f *FlagClause) OverrideDefaultFromEnvar(envar string) *FlagClause {
	return f.Envar(envar)
}

// Envar overrides the default value(s) for a flag from an environment variable,
// if it is set. Several default values can be provided by using new lines to
// separate them.
func (f *FlagClause) Envar(name string) *FlagClause {
	f.envar = name
	f.noEnvar = false
	return f
}

// NoEnvar forces environment variable defaults to be disabled for this flag.
// Most useful in conjunction with app.DefaultEnvars().
func (f *FlagClause) NoEnvar() *FlagClause {
	f.envar = ""
	f.noEnvar = true
	return f
}

// PlaceHolder sets the place-holder string used for flag values in the help. The
// default behaviour is to use the value provided by Default() if provided,
// then fall back on the capitalized flag name.
func (f *FlagClause) PlaceHolder(placeholder string) *FlagClause {
	f.placeholder = placeholder
	return f
}

// Hidden hides a flag from usage but still allows it to be used.
func (f *FlagClause) Hidden() *FlagClause {
	f.hidden = true
	return f
}

// Required makes the flag required. You can not provide a Default() value to a Required() flag.
func (f *FlagClause) Required() *FlagClause {
	f.required = true
	return f
}

// Short sets the short flag name.
func (f *FlagClause) Short(name rune) *FlagClause {
	f.shorthand = name
	return f
}

// Bool makes this flag a boolean flag.
func (f *FlagClause) Bool() (target *bool) {
	target = new(bool)
	f.SetValue(newBoolValue(target))
	return
}
