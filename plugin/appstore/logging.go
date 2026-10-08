// SPDX-License-Identifier: AGPL-3.0-or-later

package appstore

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"time"
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

// warnOnce logs msg as a warning unless the last warning logged for key was
// the same message, and reports whether it logged. For a condition the
// rescan finds again on every tick: logged when it starts or changes, not
// every few seconds. clearWarned forgets key once the condition is over, so
// it is logged again if it comes back.
func (s *supervisor) warnOnce(key, msg string) bool {
	s.sigMu.Lock()
	same := s.warned[key] == msg
	s.warned[key] = msg
	s.sigMu.Unlock()
	if same {
		return false
	}
	s.logger.Warnf("%s", msg)
	return true
}

func (s *supervisor) clearWarned(key string) {
	s.sigMu.Lock()
	delete(s.warned, key)
	s.sigMu.Unlock()
}

// markReinstalled and takeReinstalled carry watchSocket's "the install was
// replaced" to the supervise loop, so that exit is not counted as a crash.
func (s *supervisor) markReinstalled(id string) {
	s.mu.Lock()
	s.reinstalled[id] = true
	s.mu.Unlock()
}

func (s *supervisor) takeReinstalled(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.reinstalled[id]
	delete(s.reinstalled, id)
	return r
}

// rescanInterval is how often run() rescans the install root.
func (s *supervisor) rescanInterval() time.Duration {
	if s.cfg.RescanInterval > 0 {
		return s.cfg.RescanInterval
	}
	return defaultRescanInterval
}
