// SPDX-License-Identifier: AGPL-3.0-or-later

package appstore

import (
	"context"
	"fmt"
	"log"
	"log/slog"
)

// appLogger carries the app store's messages with a level: Printf for
// routine ones, Warnf for problems an operator may need to act on. With
// Config.Slog set they go to that logger (the daemon's log, where a reader
// tells problems from routine by level); otherwise to the *log.Logger as
// before, which has no levels.
type appLogger struct {
	std *log.Logger
	sl  *slog.Logger
}

func newAppLogger(std *log.Logger, sl *slog.Logger) *appLogger {
	return &appLogger{std: std, sl: sl}
}

// Printf logs a routine message (INFO).
func (l *appLogger) Printf(format string, args ...any) {
	l.logf(slog.LevelInfo, format, args...)
}

// Warnf logs a problem (WARN).
func (l *appLogger) Warnf(format string, args ...any) {
	l.logf(slog.LevelWarn, format, args...)
}

func (l *appLogger) logf(level slog.Level, format string, args ...any) {
	if l.sl != nil {
		l.sl.Log(context.Background(), level, "appstore: "+fmt.Sprintf(format, args...))
		return
	}
	l.std.Printf(format, args...)
}
