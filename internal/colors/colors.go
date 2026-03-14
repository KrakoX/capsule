package colors

// ANSI color codes
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Gray   = "\033[90m"
	Bold   = "\033[1m"
)

// Colorize wraps text in color codes
func Colorize(text, color string) string {
	return color + text + Reset
}

// Critical returns red colored text
func Critical(text string) string {
	return Red + text + Reset
}

// High returns red colored text
func High(text string) string {
	return Red + text + Reset
}

// Medium returns yellow colored text
func Medium(text string) string {
	return Yellow + text + Reset
}

// Low returns green colored text
func Low(text string) string {
	return Green + text + Reset
}

// Good returns green colored text
func Good(text string) string {
	return Green + text + Reset
}

// Warning returns yellow colored text
func Warning(text string) string {
	return Yellow + text + Reset
}

// Info returns blue colored text
func Info(text string) string {
	return Blue + text + Reset
}

// Header returns bold text
func Header(text string) string {
	return Bold + text + Reset
}

// GrayText returns gray colored text
func GrayText(text string) string {
	return Gray + text + Reset
}
