package main

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

type field struct {
	label string
	input textinput.Model
}

type form struct {
	title  string
	fields []field
	focus  int
	back   screen // where esc on the form returns to
	// build validates the values and returns the confirm request to show.
	build func(m model, vals []string) (confirmReq, error)
}

func newField(label, value, placeholder string) field {
	ti := textinput.New()
	ti.SetValue(value)
	ti.Placeholder = placeholder
	return field{label: label, input: ti}
}

// parseWhen accepts "now", "+Nd", "YYYY-MM-DD" (UTC midnight) or RFC3339.
func parseWhen(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "now":
		return now, nil
	case strings.HasPrefix(s, "+") && strings.HasSuffix(s, "d"):
		n, err := strconv.Atoi(s[1 : len(s)-1])
		if err != nil {
			return time.Time{}, fmt.Errorf("bad relative time %q", s)
		}
		return now.Add(time.Duration(n) * 24 * time.Hour), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("time %q: use now, +90d, 2027-01-01 or RFC3339", s)
}

func optionalWhen(s string, now time.Time) (*time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	t, err := parseWhen(s, now)
	return &t, err
}

func atoiField(label, s string) (int, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%s must be a number", label)
	}
	return n, nil
}

func (m model) openForm(s screen, f form) model {
	f.fields[0].input.Focus()
	// Not m.back, which the confirm screen overwrites with the form's screen.
	f.back = m.screen
	m.form, m.screen, m.err, m.note = f, s, "", ""
	return m
}

func (m model) openCreate() model {
	return m.openForm(screenCreate, form{
		title: "New issuer",
		fields: []field{
			newField("name", "", "issuer_type"),
			newField("version", "3", "1, 2 or 3"),
			newField("cohort", "1", ""),
			newField("max_tokens", "40", ""),
			newField("expires_at", "", "blank = none (v1/v2); required for v3"),
			newField("valid_from (v3)", "", "blank = now"),
			newField("duration (v3)", "P1M", "ISO 8601"),
			newField("buffer (v3)", "1", ""),
			newField("overlap (v3)", "0", ""),
		},
		build: func(m model, v []string) (confirmReq, error) {
			now := time.Now()
			req := adminapi.CreateIssuerRequest{Name: strings.TrimSpace(v[0])}
			var err error
			if req.Version, err = atoiField("version", v[1]); err != nil {
				return confirmReq{}, err
			}
			var c int64 // blank = server default cohort
			if cs := strings.TrimSpace(v[2]); cs != "" {
				if c, err = strconv.ParseInt(cs, 10, 16); err != nil {
					return confirmReq{}, fmt.Errorf("cohort must be a number between %d and %d", math.MinInt16, math.MaxInt16)
				}
			}
			req.Cohort = int16(c)
			if req.MaxTokens, err = atoiField("max_tokens", v[3]); err != nil {
				return confirmReq{}, err
			}
			if req.ExpiresAt, err = optionalWhen(v[4], now); err != nil {
				return confirmReq{}, err
			}
			if req.Version == 3 {
				if req.ValidFrom, err = optionalWhen(v[5], now); err != nil {
					return confirmReq{}, err
				}
				req.Duration = strings.TrimSpace(v[6])
				if req.Buffer, err = atoiField("buffer", v[7]); err != nil {
					return confirmReq{}, err
				}
				if req.Overlap, err = atoiField("overlap", v[8]); err != nil {
					return confirmReq{}, err
				}
			}
			return confirmReq{
				title: "Create issuer " + req.Name,
				body:  req,
				run: send("created "+req.Name, func(ctx context.Context) (*adminapi.Issuer, error) {
					return m.api.CreateIssuer(ctx, req)
				}),
			}, nil
		},
	})
}

func (m model) openEdit(cur adminapi.Issuer) model {
	exp := ""
	if cur.ExpiresAt != nil {
		exp = cur.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return m.openForm(screenEdit, form{
		title: "Edit " + cur.Name + " (only max_tokens and a later expires_at)",
		fields: []field{
			newField("max_tokens", strconv.Itoa(cur.MaxTokens), ""),
			newField("expires_at", exp, "later than current; blank = unchanged"),
		},
		build: func(m model, v []string) (confirmReq, error) {
			req := adminapi.UpdateIssuerRequest{}
			if strings.TrimSpace(v[0]) != "" {
				mt, err := atoiField("max_tokens", v[0])
				if err != nil {
					return confirmReq{}, err
				}
				if mt != cur.MaxTokens {
					req.MaxTokens = &mt
				}
			}
			if strings.TrimSpace(v[1]) != exp && strings.TrimSpace(v[1]) != "" {
				t, err := parseWhen(v[1], time.Now())
				if err != nil {
					return confirmReq{}, err
				}
				if cur.ExpiresAt == nil || !t.After(*cur.ExpiresAt) {
					return confirmReq{}, fmt.Errorf("expires_at can only move later")
				}
				req.ExpiresAt = &t
			}
			if req.MaxTokens == nil && req.ExpiresAt == nil {
				return confirmReq{}, fmt.Errorf("nothing changed")
			}
			return confirmReq{
				title: "Update " + cur.Name,
				body:  req,
				run: send("updated", func(ctx context.Context) (*adminapi.Issuer, error) {
					return m.api.UpdateIssuer(ctx, cur.ID, req)
				}),
			}, nil
		},
	})
}

func (m model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	f := &m.form
	switch k.String() {
	case "esc":
		m.screen = f.back
		return m, nil
	case "tab", "down":
		f.fields[f.focus].input.Blur()
		f.focus = (f.focus + 1) % len(f.fields)
		f.fields[f.focus].input.Focus()
		return m, nil
	case "shift+tab", "up":
		f.fields[f.focus].input.Blur()
		f.focus = (f.focus + len(f.fields) - 1) % len(f.fields)
		f.fields[f.focus].input.Focus()
		return m, nil
	case "enter":
		vals := make([]string, len(f.fields))
		for i := range f.fields {
			vals[i] = f.fields[i].input.Value()
		}
		req, err := f.build(m, vals)
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		return m.askConfirm(m.screen, req), nil
	}
	var cmd tea.Cmd
	f.fields[f.focus].input, cmd = f.fields[f.focus].input.Update(msg)
	return m, cmd
}

func (m model) formView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(m.form.title) + "\n\n")
	for _, f := range m.form.fields {
		fmt.Fprintf(&b, "%-18s %s\n", f.label, f.input.View())
	}
	b.WriteString("\n" + helpStyle.Render("tab next · enter review · esc back"))
	return b.String()
}

func (m model) openPostpone(cur adminapi.Issuer) model {
	return m.openForm(screenEdit, form{
		title: "Postpone stop-issuing for " + cur.Name + " (resumes issuing; redemption only ever extends)",
		fields: []field{
			newField("stop_issuing_at", "+30d", "later than "+fmtTime(cur.StopIssuingAt)),
			newField("stop_redeeming_at", "", "blank = keep ≥ 3 months after stop issuing"),
		},
		build: func(m model, v []string) (confirmReq, error) {
			now := time.Now()
			si, err := parseWhen(v[0], now)
			if err != nil {
				return confirmReq{}, err
			}
			req := adminapi.PostponeRequest{StopIssuingAt: si}
			if req.StopRedeemingAt, err = optionalWhen(v[1], now); err != nil {
				return confirmReq{}, err
			}
			return confirmReq{
				title:         "Postpone stop-issuing for " + cur.Name,
				body:          req,
				typeToConfirm: cur.Name,
				run: send("stop-issuing postponed", func(ctx context.Context) (*adminapi.Issuer, error) {
					return m.api.PostponeRetirement(ctx, cur.ID, req)
				}),
			}, nil
		},
	})
}

type retireWizard struct {
	target        adminapi.Issuer
	candidates    []adminapi.Issuer
	pick          int
	step          int // 0 pick replacement, 1 stop issuing, 2 stop redeeming
	stopIssuing   textinput.Model
	stopRedeeming textinput.Model
}

// defaultRetireTimes returns stop issuing now, and stop redeeming at the
// latest of three times. They are MinStopRedeeming(now) plus a day, which
// covers the server's replica and cache margin, the latest existing key end,
// and (v3) the end of every key window the cron can still create.
func defaultRetireTimes(target adminapi.Issuer, now time.Time) (time.Time, time.Time) {
	sr := adminapi.MinStopRedeeming(now).Add(24 * time.Hour)
	if target.Version >= 3 {
		if target.LatestKeyEnd != nil && target.LatestKeyEnd.After(sr) {
			sr = *target.LatestKeyEnd
		}
		if target.Duration != nil {
			if w, err := adminapi.WindowsEnd(*target.Duration, target.Buffer+target.Overlap, now); err == nil && w.After(sr) {
				sr = w
			}
		}
	}
	return now, sr
}

func (m model) openRetire(cur adminapi.Issuer) model {
	if cur.Status != adminapi.StatusActive {
		m.err = "only an active issuer can be retired (this one is " + string(cur.Status) + ")"
		return m
	}
	w := retireWizard{target: cur}
	for _, i := range m.issuers {
		if i.ID != cur.ID && i.Status == adminapi.StatusActive {
			w.candidates = append(w.candidates, i)
		}
	}
	if len(w.candidates) == 0 {
		m.err = "no active issuer to use as replacement: create one first (list → n)"
		return m
	}
	// The defaults are relative and resolved when the request is sent. An
	// absolute "now" taken here goes stale while the operator reviews and
	// types the confirmation, and the server allows only a minute of skew.
	si, sr := defaultRetireTimes(cur, time.Now())
	w.stopIssuing = textinput.New()
	w.stopIssuing.SetValue("now")
	w.stopRedeeming = textinput.New()
	w.stopRedeeming.SetValue(fmt.Sprintf("+%dd", int(math.Ceil(sr.Sub(si).Hours()/24))))
	m.retire, m.back, m.screen, m.err, m.note = w, screenDetail, screenRetire, "", ""
	return m
}

func (m model) updateRetire(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	w := &m.retire
	switch k.String() {
	case "esc":
		switch w.step {
		case 0:
			m.screen = screenDetail
		case 1:
			w.stopIssuing.Blur()
			w.step = 0
		case 2:
			w.stopRedeeming.Blur()
			w.step = 1
			w.stopIssuing.Focus()
		}
		return m, nil
	case "enter":
		switch w.step {
		case 0:
			w.step = 1
			w.stopIssuing.Focus()
		case 1:
			w.stopIssuing.Blur()
			w.step = 2
			w.stopRedeeming.Focus()
		case 2:
			target, repl := w.target, w.candidates[w.pick]
			siIn, srIn := w.stopIssuing.Value(), w.stopRedeeming.Value()
			req, err := retireRequest(repl.ID, siIn, srIn, time.Now())
			if err != nil {
				m.err = err.Error()
				return m, nil
			}
			return m.askConfirm(screenRetire, confirmReq{
				title: fmt.Sprintf("Retire %s → replacement %s. %s stops issuing at %s (%s) and stops redeeming at %s (%s). Clients must request %s from then on.",
					target.Name, repl.Name, target.Name, siIn, fmtTime(&req.StopIssuingAt), srIn, fmtTime(&req.StopRedeemingAt), repl.Name),
				body:          req,
				typeToConfirm: target.Name,
				run: send("retirement scheduled", func(ctx context.Context) (*adminapi.Issuer, error) {
					// Re-resolve "now" and "+Nd" at send time. Absolute times are unchanged.
					req, err := retireRequest(repl.ID, siIn, srIn, time.Now())
					if err != nil {
						return nil, err
					}
					return m.api.RetireIssuer(ctx, target.ID, req)
				}),
			}), nil
		}
		return m, nil
	case "up", "k":
		if w.step == 0 && w.pick > 0 {
			w.pick--
			return m, nil
		}
	case "down", "j":
		if w.step == 0 && w.pick < len(w.candidates)-1 {
			w.pick++
			return m, nil
		}
	}
	var cmd tea.Cmd
	switch w.step {
	case 1:
		w.stopIssuing, cmd = w.stopIssuing.Update(msg)
	case 2:
		w.stopRedeeming, cmd = w.stopRedeeming.Update(msg)
	}
	return m, cmd
}

func retireRequest(replID, stopIssuing, stopRedeeming string, now time.Time) (adminapi.RetireRequest, error) {
	si, err := parseWhen(stopIssuing, now)
	if err != nil {
		return adminapi.RetireRequest{}, err
	}
	sr, err := parseWhen(stopRedeeming, now)
	if err != nil {
		return adminapi.RetireRequest{}, err
	}
	if sr.Before(adminapi.MinStopRedeeming(si)) {
		return adminapi.RetireRequest{}, fmt.Errorf("stop redeeming must be at least 3 months (and 90 days) after stop issuing")
	}
	return adminapi.RetireRequest{ReplacementIssuerID: replID, StopIssuingAt: si, StopRedeemingAt: sr}, nil
}

func (m model) retireView() string {
	w := m.retire
	var b strings.Builder
	b.WriteString(titleStyle.Render("Retire "+w.target.Name) + "\n\n")
	b.WriteString("1. Replacement (active issuers only):\n")
	for i, c := range w.candidates {
		cursor := "  "
		if i == w.pick {
			cursor = "> "
		}
		fmt.Fprintf(&b, "%s%s (v%d, cohort %d, expires %s)\n", cursor, c.Name, c.Version, c.Cohort, fmtTime(c.ExpiresAt))
	}
	if w.step >= 1 {
		b.WriteString("\n2. Stop issuing at: " + w.stopIssuing.View() + "\n")
	}
	if w.step >= 2 {
		b.WriteString("3. Stop redeeming at (≥ 3 months later): " + w.stopRedeeming.View() + "\n")
	}
	b.WriteString("\n" + helpStyle.Render("↑/↓ pick · enter next · esc back · times: now, +90d, 2027-01-01, RFC3339"))
	return b.String()
}
