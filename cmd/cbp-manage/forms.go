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
	m.form, m.screen, m.back, m.err, m.note = f, s, m.screen, "", ""
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
			c, err := int64(0), error(nil) // blank = server default cohort
			if cs := strings.TrimSpace(v[2]); cs != "" {
				c, err = strconv.ParseInt(cs, 10, 16)
			}
			if err != nil {
				return confirmReq{}, fmt.Errorf("cohort must be a number between %d and %d", math.MinInt16, math.MaxInt16)
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
				run: func() tea.Cmd {
					return func() tea.Msg {
						iss, err := m.api.CreateIssuer(context.Background(), req)
						if err != nil {
							return errMsg{err}
						}
						return doneMsg{iss, "created " + iss.Name}
					}
				},
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
			if mt, err := atoiField("max_tokens", v[0]); err != nil {
				return confirmReq{}, err
			} else if mt != cur.MaxTokens {
				req.MaxTokens = &mt
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
				run: func() tea.Cmd {
					return func() tea.Msg {
						iss, err := m.api.UpdateIssuer(context.Background(), cur.ID, req)
						if err != nil {
							return errMsg{err}
						}
						return doneMsg{iss, "updated"}
					}
				},
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
		m.screen = m.back
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
			newField("stop_redeeming_at", "", "blank = keep ≥ 90 days after stop issuing"),
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
				run: func() tea.Cmd {
					return func() tea.Msg {
						iss, err := m.api.PostponeRetirement(context.Background(), cur.ID, req)
						if err != nil {
							return errMsg{err}
						}
						return doneMsg{iss, "stop-issuing postponed"}
					}
				},
			}, nil
		},
	})
}

// ---- retire wizard ----

type retireWizard struct {
	target        adminapi.Issuer
	candidates    []adminapi.Issuer
	pick          int
	step          int // 0 pick replacement, 1 stop issuing, 2 stop redeeming
	stopIssuing   textinput.Model
	stopRedeeming textinput.Model
}

// defaultRetireTimes: stop issuing now; stop redeeming at the later of
// now+90d and (v3) the furthest key window the cron can still create.
func defaultRetireTimes(target adminapi.Issuer, now time.Time) (time.Time, time.Time) {
	sr := now.Add(adminapi.MinRetirementOverlap)
	if target.Version >= 3 {
		if target.LatestKeyEnd != nil && target.LatestKeyEnd.After(sr) {
			sr = *target.LatestKeyEnd
		}
		// ponytail: approximates the server's ISO-duration walk with 31-day
		// months; the server is authoritative and returns the exact minimum.
		if target.Duration != nil {
			if n, unit, ok := simpleISO(*target.Duration); ok {
				w := now.Add(time.Duration(n*(target.Buffer+target.Overlap)) * unit)
				if w.After(sr) {
					sr = w
				}
			}
		}
	}
	return now, sr
}

// simpleISO parses PnD / PnM / PnY / PTnH for the default only.
func simpleISO(d string) (int, time.Duration, bool) {
	units := map[string]time.Duration{"D": 24 * time.Hour, "M": 31 * 24 * time.Hour, "Y": 366 * 24 * time.Hour, "H": time.Hour}
	s := strings.TrimPrefix(strings.TrimPrefix(d, "P"), "T")
	if len(s) < 2 {
		return 0, 0, false
	}
	u, ok := units[s[len(s)-1:]]
	n, err := strconv.Atoi(s[:len(s)-1])
	return n, u, ok && err == nil
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
	si, sr := defaultRetireTimes(cur, time.Now())
	w.stopIssuing = textinput.New()
	w.stopIssuing.SetValue(si.UTC().Format(time.RFC3339))
	w.stopRedeeming = textinput.New()
	w.stopRedeeming.SetValue(sr.UTC().Format(time.RFC3339))
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
		if w.step == 0 {
			m.screen = screenDetail
		} else {
			w.step--
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
			now := time.Now()
			si, err := parseWhen(w.stopIssuing.Value(), now)
			if err != nil {
				m.err = err.Error()
				return m, nil
			}
			sr, err := parseWhen(w.stopRedeeming.Value(), now)
			if err != nil {
				m.err = err.Error()
				return m, nil
			}
			if sr.Sub(si) < adminapi.MinRetirementOverlap {
				m.err = "stop redeeming must be at least 90 days after stop issuing"
				return m, nil
			}
			target, repl := w.target, w.candidates[w.pick]
			req := adminapi.RetireRequest{ReplacementIssuerID: repl.ID, StopIssuingAt: si, StopRedeemingAt: sr}
			return m.askConfirm(screenRetire, confirmReq{
				title: fmt.Sprintf("Retire %s → replacement %s. %s stops issuing at %s and stops redeeming at %s. Clients must request %s from then on.",
					target.Name, repl.Name, target.Name, fmtTime(&si), fmtTime(&sr), repl.Name),
				body:          req,
				typeToConfirm: target.Name,
				run: func() tea.Cmd {
					return func() tea.Msg {
						iss, err := m.api.RetireIssuer(context.Background(), target.ID, req)
						if err != nil {
							return errMsg{err}
						}
						return doneMsg{iss, "retirement scheduled"}
					}
				},
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
		b.WriteString("3. Stop redeeming at (≥ 90 days later): " + w.stopRedeeming.View() + "\n")
	}
	b.WriteString("\n" + helpStyle.Render("↑/↓ pick · enter next · esc back · times: now, +90d, 2027-01-01, RFC3339"))
	return b.String()
}
