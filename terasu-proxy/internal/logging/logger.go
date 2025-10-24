package logging

import (
    "os"
    "strings"

    "github.com/sirupsen/logrus"
)

func Setup(level string) *logrus.Logger {
    logger := logrus.New()
    logger.SetOutput(os.Stdout)
    logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
    if level == "" {
        level = "info"
    }
    lv, err := logrus.ParseLevel(strings.ToLower(level))
    if err != nil {
        lv = logrus.InfoLevel
    }
    logger.SetLevel(lv)
    return logger
}


