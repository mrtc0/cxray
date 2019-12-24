package logger

import (
	log "github.com/sirupsen/logrus"
)

type Logger struct {
	Logger *log.Logger
}

type LogOption func(*log.Logger)

func Format() LogOption {
	return func(logger *log.Logger) {
		logger.SetFormatter(&log.TextFormatter{})
	}
}

func New(options ...LogOption) *Logger {
	logger := &Logger{Logger: log.New()}
	for _, option := range options {
		option(logger.Logger)
	}
	return logger
}

func (logger *Logger) Info(msg string, data map[string]interface{}) {
	logger.Logger.WithFields(data).Info(msg)
}
