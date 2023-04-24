package oidclogin

type Level string

const (
	LogInfo  Level = "info"
	LogError Level = "error"
	LogWarn  Level = "warn"
)

type Logger interface {
	Log(level Level, message string)
}

type LoggerFunc func(level Level, message string)

func (lf LoggerFunc) Log(level Level, message string) {
	lf(level, message)
}
