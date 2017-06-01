package kingpin

import (
	"fmt"
	"strconv"
	"strings"
)

// Data model for Kingpin command-line structure.

type FlagGroupModel struct {
	Flags []*FlagModel
}

func (f *FlagGroupModel) FlagSummary() string {
	out := []string{}
	count := 0
	for _, flag := range f.Flags {
		if flag.Name != "help" {
			count++
		}
		if flag.Required {
			if flag.IsBoolFlag() {
				out = append(out, fmt.Sprintf("--[no-]%s", flag.Name))
			} else {
				out = append(out, fmt.Sprintf("--%s=%s", flag.Name, flag.FormatPlaceHolder()))
			}
		}
	}
	if count != len(out) {
		out = append(out, "[<flags>]")
	}
	return strings.Join(out, " ")
}

type FlagModel struct {
	Name        string
	Help        string
	Short       rune
	Default     []string
	Envar       string
	PlaceHolder string
	Required    bool
	Hidden      bool
	Value       Value
}

func (f *FlagModel) String() string {
	return f.Value.String()
}

func (f *FlagModel) IsBoolFlag() bool {
	if fl, ok := f.Value.(boolFlag); ok {
		return fl.IsBoolFlag()
	}
	return false
}

func (f *FlagModel) FormatPlaceHolder() string {
	if f.PlaceHolder != "" {
		return f.PlaceHolder
	}
	if len(f.Default) > 0 {
		ellipsis := ""
		if len(f.Default) > 1 {
			ellipsis = "..."
		}
		if _, ok := f.Value.(*stringValue); ok {
			return strconv.Quote(f.Default[0]) + ellipsis
		}
		return f.Default[0] + ellipsis
	}
	return strings.ToUpper(f.Name)
}

type ArgGroupModel struct {
	Args []*ArgModel
}

func (a *ArgGroupModel) ArgSummary() string {
	depth := 0
	out := []string{}
	for _, arg := range a.Args {
		h := "<" + arg.Name + ">"
		if !arg.Required {
			h = "[" + h
			depth++
		}
		out = append(out, h)
	}
	out[len(out)-1] = out[len(out)-1] + strings.Repeat("]", depth)
	return strings.Join(out, " ")
}

type ArgModel struct {
	Name     string
	Help     string
	Default  []string
	Envar    string
	Required bool
	Value    Value
}

func (a *ArgModel) String() string {
	return a.Value.String()
}

type CmdGroupModel struct {
	Commands []*CmdModel
}

func (c *CmdGroupModel) FlattenedCommands() (out []*CmdModel) {
	for _, cmd := range c.Commands {
		if len(cmd.Commands) == 0 {
			out = append(out, cmd)
		}
		out = append(out, cmd.FlattenedCommands()...)
	}
	return
}

type CmdModel struct {
	Name        string
	Aliases     []string
	Help        string
	FullCommand string
	Depth       int
	Hidden      bool
	Default     bool
	*FlagGroupModel
	*ArgGroupModel
	*CmdGroupModel
}

func (c *CmdModel) String() string {
	return c.FullCommand
}

type ApplicationModel struct {
	Name    string
	Help    string
	Version string
	Author  string
	*ArgGroupModel
	*CmdGroupModel
	*FlagGroupModel
}

func (a *Application) Model() *ApplicationModel {
	return &ApplicationModel{
		Name:           a.Name,
		Help:           a.Help,
		Version:        a.version,
		Author:         a.author,
		FlagGroupModel: a.flagGroup.Model(),
		ArgGroupModel:  a.argGroup.Model(),
		CmdGroupModel:  a.cmdGroup.Model(),
	}
}

func (a *argGroup) Model() *ArgGroupModel {
	m := &ArgGroupModel{}
	for _, arg := range a.args {
		m.Args = append(m.Args, arg.Model())
	}
	return m
}

func (a *ArgClause) Model() *ArgModel {
	return &ArgModel{
		Name:     a.name,
		Help:     a.help,
		Default:  a.defaultValues,
		Envar:    a.envar,
		Required: a.required,
		Value:    a.value,
	}
}

func (f *flagGroup) Model() *FlagGroupModel {
	m := &FlagGroupModel{}
	for _, fl := range f.flagOrder {
		m.Flags = append(m.Flags, fl.Model())
	}
	return m
}

func (f *FlagClause) Model() *FlagModel {
	return &FlagModel{
		Name:        f.name,
		Help:        f.help,
		Short:       rune(f.shorthand),
		Default:     f.defaultValues,
		Envar:       f.envar,
		PlaceHolder: f.placeholder,
		Required:    f.required,
		Hidden:      f.hidden,
		Value:       f.value,
	}
}

func (c *cmdGroup) Model() *CmdGroupModel {
	m := &CmdGroupModel{}
	for _, cm := range c.commandOrder {
		m.Commands = append(m.Commands, cm.Model())
	}
	return m
}

func (c *CmdClause) Model() *CmdModel {
	depth := 0
	for i := c; i != nil; i = i.parent {
		depth++
	}
	return &CmdModel{
		Name:           c.name,
		Aliases:        c.aliases,
		Help:           c.help,
		Depth:          depth,
		Hidden:         c.hidden,
		Default:        c.isDefault,
		FullCommand:    c.FullCommand(),
		FlagGroupModel: c.flagGroup.Model(),
		ArgGroupModel:  c.argGroup.Model(),
		CmdGroupModel:  c.cmdGroup.Model(),
	}
}
