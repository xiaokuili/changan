/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package loggers

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logger *zap.Logger
var slogger *zap.SugaredLogger

//LogConifg logger Config
type LogConifg struct {
	Level      string
	FileName   string
	MaxSize    int
	MaxAge     int
	MaxBackups int
}

const (
	//DEFAULT_LOG_LEVEL Default log level
	DEFAULT_LOG_LEVEL = "error"
	//DEFAULT_LOG_FILENAME Default log filename
	DEFAULT_LOG_FILENAME = "./log/ca.log"
	//DEFAULT_LOG_MAXSIZE Default log maxsize
	DEFAULT_LOG_MAXSIZE = 10
	//DEFAULT_LOG_MAXAGE Default log maxage
	DEFAULT_LOG_MAXAGE = 30
	//DEFAULT_LOG_MAXBACKUPS Default log maxbackups
	DEFAULT_LOG_MAXBACKUPS = 5
)

func checkLogConfig(logConf *LogConifg) {
	if len(logConf.Level) == 0 {
		logConf.Level = DEFAULT_LOG_LEVEL
	}
	if len(logConf.FileName) == 0 {
		logConf.FileName = DEFAULT_LOG_FILENAME
	}
	if logConf.MaxAge == 0 {
		logConf.MaxAge = DEFAULT_LOG_MAXAGE
	}
	if logConf.MaxSize == 0 {
		logConf.MaxSize = DEFAULT_LOG_MAXSIZE
	}
	if logConf.MaxBackups == 0 {
		logConf.MaxBackups = DEFAULT_LOG_MAXBACKUPS
	}
}

//InitLogger init zap logger
func InitLogger(logConf *LogConifg) error {
	checkLogConfig(logConf)
	writeSyncer := getLogWriter(logConf.FileName, logConf.MaxSize, logConf.MaxBackups, logConf.MaxAge)
	encoder := getEncoder()
	level := new(zapcore.Level)
	err := level.UnmarshalText([]byte(logConf.Level))
	if err != nil {
		return err
	}
	core := zapcore.NewCore(encoder, writeSyncer, level)
	logger = zap.New(core, zap.AddCaller())
	slogger = logger.Sugar()
	return nil
}

func getLogWriter(fileName string, maxSize, maxBackup, maxAge int) zapcore.WriteSyncer {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   fileName,
		MaxSize:    maxSize,
		MaxBackups: maxBackup,
		MaxAge:     maxAge,
	}
	return zapcore.AddSync(lumberJackLogger)
}

func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	return zapcore.NewJSONEncoder(encoderConfig)
}

//GetLogger Get normal logger
func GetLogger() *zap.Logger {
	return logger
}

//GetSugaLogger Get sugared logger
func GetSugaLogger() *zap.SugaredLogger {
	return slogger
}
