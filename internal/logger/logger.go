package logger

import (
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var Log *logrus.Logger

func Init(level string, output io.Writer) {
	Log = logrus.New()
	Log.SetOutput(output)
	Log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		TimestampFormat: "2006-01-02 15:04:02",
		ForceColors: true,
	})
	SetLevel(level)
}

func SetLevel(level string) {
	parsedLevel, err := logrus.ParseLevel(strings.ToLower(level))
	if err != nil {
		Log.Warnf("Invalid log level '%s', defaulting to info", level)
		Log.SetLevel(logrus.InfoLevel)
	} else {
		Log.SetLevel(parsedLevel)
	}
}

func init() {
	Init("info", os.Stdout)
}