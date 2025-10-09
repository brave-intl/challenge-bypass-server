package alert

import (
	"context"
	"log/slog"
)

type Alert struct {
	l *slog.Logger
}

func New(l *slog.Logger) *Alert {
	return &Alert{l: l}
}

func (a *Alert) Crash(ctx context.Context, err error) {
	a.log(ctx, "ALERT_CRASH", err)
}

func (a *Alert) Outage(ctx context.Context, err error) {
	a.log(ctx, "ALERT_OUTAGE", err)
}

func (a *Alert) Generic(ctx context.Context, err error) {
	a.log(ctx, "ALERT_TEAM", err)
}

func (a *Alert) log(ctx context.Context, code string, err error) {
	a.l.Log(ctx, slog.LevelError, "", slog.String("code", code), slog.Any("message", err))
}
