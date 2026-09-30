package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

type fakeAPI struct {
	issuers []adminapi.Issuer
	retired *adminapi.RetireRequest
	err     error
}

func (f *fakeAPI) ListIssuers(context.Context) ([]adminapi.Issuer, error) { return f.issuers, f.err }
func (f *fakeAPI) GetIssuer(_ context.Context, id string) (*adminapi.Issuer, error) {
	for _, i := range f.issuers {
		if i.ID == id {
			return &i, nil
		}
	}
	return nil, &adminapi.APIError{Status: 404, Message: "issuer not found"}
}
func (f *fakeAPI) CreateIssuer(context.Context, adminapi.CreateIssuerRequest) (*adminapi.Issuer, error) {
	return &f.issuers[0], nil
}
func (f *fakeAPI) UpdateIssuer(context.Context, string, adminapi.UpdateIssuerRequest) (*adminapi.Issuer, error) {
	return &f.issuers[0], nil
}
func (f *fakeAPI) RetireIssuer(_ context.Context, _ string, r adminapi.RetireRequest) (*adminapi.Issuer, error) {
	f.retired = &r
	return &f.issuers[0], nil
}
func (f *fakeAPI) CancelRetirement(context.Context, string) (*adminapi.Issuer, error) {
	return &f.issuers[0], nil
}
func (f *fakeAPI) PostponeRetirement(context.Context, string, adminapi.PostponeRequest) (*adminapi.Issuer, error) {
	return &f.issuers[0], nil
}
func (f *fakeAPI) ListAudit(context.Context, string, int) ([]adminapi.AuditEntry, error) {
	return nil, nil
}

func TestDescribeErrClockSkew(t *testing.T) {
	for _, st := range []int{408, 425} {
		msg := describeErr(&adminapi.APIError{Status: st, Message: "date is invalid"})
		if !strings.Contains(msg, "clock") {
			t.Errorf("%d: %q lacks clock hint", st, msg)
		}
	}
	if !strings.Contains(describeErr(&adminapi.APIError{Status: 403}), "not on the operator allowlist") {
		t.Error("403 hint missing")
	}
	if describeErr(errors.New("dial tcp: refused")) == "" {
		t.Error("network error must render")
	}
}

// drive runs a command chain synchronously (tests only).
func drive(m tea.Model, cmd tea.Cmd) tea.Model {
	for cmd != nil {
		msg := cmd()
		if msg == nil {
			break
		}
		if batch, ok := msg.(tea.BatchMsg); ok {
			for _, c := range batch {
				m = drive(m, c)
			}
			return m
		}
		m, cmd = m.Update(msg)
	}
	return m
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func typeText(m tea.Model, s string) tea.Model {
	for _, r := range s {
		// cmds dropped on purpose: textinput returns cursor-blink ticks
		m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return m
}

func TestListLoadsAndShowsStatus(t *testing.T) {
	f := &fakeAPI{issuers: []adminapi.Issuer{{ID: "1", Name: "ads-a", Version: 1, Status: adminapi.StatusRetired}}}
	var m tea.Model = newModel(f)
	m = drive(m, m.Init())
	v := m.View()
	if !strings.Contains(v, "ads-a") || !strings.Contains(v, "retired") {
		t.Fatalf("list view missing issuer/status:\n%s", v)
	}
}

func TestDefaultRetireTimes(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	si, sr := defaultRetireTimes(adminapi.Issuer{Version: 1}, now)
	if !si.Equal(now) || !sr.Equal(now.Add(adminapi.MinRetirementOverlap)) {
		t.Fatalf("v1 defaults: %v %v", si, sr)
	}
	far := now.AddDate(0, 6, 0)
	d := "P1M"
	_, sr = defaultRetireTimes(adminapi.Issuer{Version: 3, LatestKeyEnd: &far, Duration: &d, Buffer: 2, Overlap: 1}, now)
	if sr.Before(far) {
		t.Fatalf("v3 default must cover latest key end, got %v", sr)
	}
}

func TestParseWhen(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Time{
		"now":                  now,
		"+90d":                 now.Add(90 * 24 * time.Hour),
		"2027-01-01":           time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		"2027-01-01T05:00:00Z": time.Date(2027, 1, 1, 5, 0, 0, 0, time.UTC),
	}
	for in, want := range cases {
		got, err := parseWhen(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: got %v %v want %v", in, got, err, want)
		}
	}
	if _, err := parseWhen("tomorrow", now); err == nil {
		t.Error("garbage must error")
	}
}

func TestRetireWizardOffersOnlyActiveReplacementsAndRequiresTypedName(t *testing.T) {
	f := &fakeAPI{issuers: []adminapi.Issuer{
		{ID: "1", Name: "old", Version: 1, Status: adminapi.StatusActive},
		{ID: "2", Name: "new", Version: 1, Status: adminapi.StatusActive},
		{ID: "3", Name: "gone", Version: 1, Status: adminapi.StatusRetired},
	}}
	var m tea.Model = newModel(f)
	m = drive(m, m.Init())
	m, _ = m.Update(key("enter")) // open "gone"? table sorted as given: row 0 = old
	m = drive(m, func() tea.Msg { return detailMsg{iss: &f.issuers[0]} })
	m, _ = m.Update(key("R"))
	mm := m.(model)
	if len(mm.retire.candidates) != 1 || mm.retire.candidates[0].ID != "2" {
		t.Fatalf("candidates: %+v", mm.retire.candidates)
	}
	// accept defaults through to confirm
	for i := 0; i < 3; i++ {
		m, _ = m.Update(key("enter"))
	}
	if m.(model).screen != screenConfirm {
		t.Fatalf("expected confirm screen, got %v", m.(model).screen)
	}
	m, _ = m.Update(key("enter")) // no typed name
	if f.retired != nil {
		t.Fatal("retire sent without typed confirmation")
	}
	m = typeText(m, "old")
	var cmd tea.Cmd
	m, cmd = m.Update(key("enter"))
	drive(m, cmd)
	if f.retired == nil || f.retired.ReplacementIssuerID != "2" {
		t.Fatalf("retire not sent correctly: %+v", f.retired)
	}
	if f.retired.StopRedeemingAt.Sub(f.retired.StopIssuingAt) < adminapi.MinRetirementOverlap {
		t.Fatal("default overlap below 90 days")
	}
}
