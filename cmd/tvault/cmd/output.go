package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

var (
	// Color definitions.
	successColor = color.New(color.FgGreen)
	errorColor   = color.New(color.FgRed)
	warningColor = color.New(color.FgYellow)
	infoColor    = color.New(color.FgCyan)
	boldColor    = color.New(color.Bold)
	dimColor     = color.New(color.Faint)
)

// Success prints a success message in green.
func Success(format string, a ...any) {
	successColor.Fprintf(os.Stdout, "✓ "+format+"\n", a...)
}

// Error prints an error message in red.
func Error(format string, a ...any) {
	errorColor.Fprintf(os.Stderr, "✗ "+format+"\n", a...)
}

// Warning prints a warning message in yellow.
func Warning(format string, a ...any) {
	warningColor.Fprintf(os.Stdout, "⚠ "+format+"\n", a...)
}

// Info prints an info message in cyan.
func Info(format string, a ...any) {
	infoColor.Fprintf(os.Stdout, "ℹ "+format+"\n", a...)
}

// Bold prints text in bold.
func Bold(format string, a ...any) string {
	return boldColor.Sprintf(format, a...)
}

// Dim prints text in dim/faint style.
func Dim(format string, a ...any) string {
	return dimColor.Sprintf(format, a...)
}

// SuccessIcon returns a green checkmark.
func SuccessIcon() string {
	return successColor.Sprint("✓")
}

// ErrorIcon returns a red X.
func ErrorIcon() string {
	return errorColor.Sprint("✗")
}

// WarningIcon returns a yellow warning sign.
func WarningIcon() string {
	return warningColor.Sprint("⚠")
}

// InfoIcon returns a cyan info symbol.
func InfoIcon() string {
	return infoColor.Sprint("ℹ")
}

// PromptConfirm asks for user confirmation and returns true if confirmed.
func PromptConfirm(message string) bool {
	fmt.Printf("%s [y/N]: ", message)

	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		return false
	}

	return response == "y" || response == "Y" || response == "yes" || response == "Yes" || response == "YES"
}

// PrintKeyValue prints a key-value pair with the key highlighted.
func PrintKeyValue(key, value string) {
	fmt.Printf("%s: %s\n", boldColor.Sprint(key), value)
}

// PrintTableHeader prints a table header with bold column names.
func PrintTableHeader(columns ...string) {
	for i, col := range columns {
		if i > 0 {
			fmt.Print("\t")
		}
		fmt.Print(boldColor.Sprint(col))
	}
	fmt.Println()
}
