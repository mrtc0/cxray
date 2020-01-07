package logger

import (
	"io"

	log "github.com/sirupsen/logrus"
)

// EventLog is a common log struct
type EventLog struct {
	ContainerID string `json:"container_id"`
	Event       Event  `json:"event"`
}

// Event is a event log struct
// Data filed is map[string]string because the field varies by syscall
type Event struct {
	Name string            `json:"name"`
	Data map[string]string `json:"data"`
}

// Logger is a common logger struct
type Logger struct {
	Logger *log.Logger
}

// LogOption is a log option
type LogOption func(*log.Logger)

// Format is set a log format
// default is JSON format
// More formats will be support in the future
func Format() LogOption {
	return func(logger *log.Logger) {
		logger.SetFormatter(&log.JSONFormatter{})
	}
}

func Output(w io.Writer) LogOption {
	return func(logger *log.Logger) {
		logger.SetOutput(w)
	}
}

// New is create logger
// New(Format(...)) can set a format
func New(options ...LogOption) *Logger {
	logger := &Logger{Logger: log.New()}
	for _, option := range options {
		option(logger.Logger)
	}
	return logger
}

// Info is info log
func (logger *Logger) Info(msg string, data EventLog) {
	logger.Logger.WithFields(log.Fields{
		"data": data,
	}).Info(msg)
}

func (logger *Logger) Fatal(msg error) {
	logger.Logger.Fatal(msg)
}
