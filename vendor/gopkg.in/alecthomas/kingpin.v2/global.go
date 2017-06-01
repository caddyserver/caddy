package kingpin

import (
	"os"
	"path/filepath"
)

var (
	// CommandLine is the default Kingpin parser.
	CommandLine = New(filepath.Base(os.Args[0]), "")
	// Global help flag. Exposed for user customisation.
	HelpFlag = CommandLine.HelpFlag
	// Top-level help command. Exposed for user customisation. May be nil.
	HelpCommand = CommandLine.HelpCommand
	// Global version flag. Exposed for user customisation. May be nil.
	VersionFlag = CommandLine.VersionFlag
)

// Command adds a new command to the default parser.
func Command(name, help string) *CmdClause {
	return CommandLine.Command(name, help)
}

// Flag adds a new flag to the default parser.
func Flag(name, help string) *FlagClause {
	return CommandLine.Flag(name, help)
}

// Arg adds a new argument to the top-level of the default parser.
func Arg(name, help string) *ArgClause {
	return CommandLine.Arg(name, help)
}

// Parse and return the selected command. Will call the termination handler if
// an error is encountered.
func Parse() string {
	selected := MustParse(CommandLine.Parse(os.Args[1:]))
	if selected == "" && CommandLine.cmdGroup.have() {
		Usage()
		CommandLine.terminate(0)
	}
	return selected
}

// Errorf prints an error message to stderr.
func Errorf(format string, args ...interface{}) {
	CommandLine.Errorf(format, args...)
}

// Fatalf prints an error message to stderr and exits.
func Fatalf(format string, args ...interface{}) {
	CommandLine.Fatalf(format, args...)
}

// FatalIfError prints an error and exits if err is not nil. The error is printed
// with the given prefix.
func FatalIfError(err error, format string, args ...interface{}) {
	CommandLine.FatalIfError(err, format, args...)
}

// FatalUsage prints an error message followed by usage information, then
// exits with a non-zero status.
func FatalUsage(format string, args ...interface{}) {
	CommandLine.FatalUsage(format, args...)
}

// FatalUsageContext writes a printf formatted error message to stderr, then
// usage information for the given ParseContext, before exiting.
func FatalUsageContext(context *ParseContext, format string, args ...interface{}) {
	CommandLine.FatalUsageContext(context, format, args...)
}

// Usage prints usage to stderr.
func Usage() {
	CommandLine.Usage(os.Args[1:])
}

// Set global usage template to use (defaults to DefaultUsageTemplate).
func UsageTemplate(template string) *Application {
	return CommandLine.UsageTemplate(template)
}

// MustParse can be used with app.Parse(args) to exit with an error if parsing fails.
func MustParse(command string, err error) string {
	if err != nil {
		Fatalf("%s, try --help", err)
	}
	return command
}

// Version adds a flag for displaying the application version number.
func Version(version string) *Application {
	return CommandLine.Version(version)
}
