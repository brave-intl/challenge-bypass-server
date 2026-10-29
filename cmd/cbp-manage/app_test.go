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
	issuers   []adminapi.Issuer
	retired   *adminapi.RetireRequest
	postponed *adminapi.PostponeRequest
	cancelled string
	err       error
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
func (f *fakeAPI) CancelRetirement(_ context.Context, id string) (*adminapi.Issuer, error) {
	f.cancelled = id
	return &f.issuers[0], nil
}
func (f *fakeAPI) PostponeRetirement(_ context.Context, _ string, r adminapi.PostponeRequest) (*adminapi.Issuer, error) {
	f.postponed = &r
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
		// The cmds are dropped on purpose. textinput returns cursor-blink ticks.
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
	if !si.Equal(now) || !sr.Equal(adminapi.MinStopRedeeming(now).Add(24*time.Hour)) {
		t.Fatalf("v1 defaults: %v %v", si, sr)
	}
	far := now.AddDate(0, 6, 0)
	d := "P1M"
	_, sr = defaultRetireTimes(adminapi.Issuer{Version: 3, LatestKeyEnd: &far, Duration: &d, Buffer: 2, Overlap: 1}, now)
	if sr.Before(far) {
		t.Fatalf("v3 default must cover latest key end, got %v", sr)
	}
	// with no keys yet, the windows the cron can still create decide it
	long := "P2M"
	_, sr = defaultRetireTimes(adminapi.Issuer{Version: 3, Duration: &long, Buffer: 2, Overlap: 1}, now)
	if want, _ := adminapi.WindowsEnd(long, 3, now); !sr.Equal(want) {
		t.Fatalf("v3 default must cover 3 x P2M windows: got %v want %v", sr, want)
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
	confirmTyped(m, "old")
	if f.retired == nil || f.retired.ReplacementIssuerID != "2" {
		t.Fatalf("retire not sent correctly: %+v", f.retired)
	}
	if f.retired.StopRedeemingAt.Before(adminapi.MinStopRedeeming(f.retired.StopIssuingAt)) {
		t.Fatal("default overlap below 3 months")
	}
	if time.Since(f.retired.StopIssuingAt) > time.Second {
		t.Fatalf("stop_issuing_at must resolve at send time, got %v", f.retired.StopIssuingAt)
	}
}

// The wizard's defaults are relative, so they resolve against the clock at
// send time, however long the operator spends on review.
func TestRetireDefaultsResolveAtSendTime(t *testing.T) {
	f, m := retireSetup()
	m = m.openRetire(f.issuers[0])
	si, sr := m.retire.stopIssuing.Value(), m.retire.stopRedeeming.Value()
	if si != "now" || !strings.HasPrefix(sr, "+") || !strings.HasSuffix(sr, "d") {
		t.Fatalf("defaults must be relative, got %q %q", si, sr)
	}
	later := time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)
	req, err := retireRequest("2", si, sr, later)
	if err != nil {
		t.Fatal(err)
	}
	if !req.StopIssuingAt.Equal(later) {
		t.Fatalf("stop_issuing_at %v, want the send time %v", req.StopIssuingAt, later)
	}
}

func TestRetireRequestNeedsThreeCalendarMonths(t *testing.T) {
	nov1 := time.Date(2027, 11, 1, 0, 0, 0, 0, time.UTC) // +90d = Jan 30, +3 months = Feb 1
	if _, err := retireRequest("2", "2027-11-01", "2028-01-30", nov1); err == nil {
		t.Fatal("90 days short of 3 months must be rejected")
	}
	if _, err := retireRequest("2", "2027-11-01", "2028-02-01", nov1); err != nil {
		t.Fatalf("3 months must pass: %v", err)
	}
}

// After a mutation succeeds the TUI must leave the confirm screen at once:
// rendering screenConfirm with a nil confirm panicked.
func TestDoneLeavesConfirmScreen(t *testing.T) {
	f := &fakeAPI{issuers: []adminapi.Issuer{{ID: "1", Name: "old", Version: 1, Status: adminapi.StatusActive}}}
	var m tea.Model = newModel(f)
	m = m.(model).askConfirm(screenDetail, confirmReq{title: "x", run: nil})
	m, _ = m.Update(doneMsg{&f.issuers[0], "ok"})
	if m.(model).screen != screenDetail {
		t.Fatalf("screen %v, want detail", m.(model).screen)
	}
	_ = m.View()
	_, _ = m.Update(key("x")) // must not panic
}

// esc on the confirm screen, then esc on the form, must get back to detail.
func TestFormEscReturnsAfterConfirmEsc(t *testing.T) {
	f := &fakeAPI{issuers: []adminapi.Issuer{{ID: "1", Name: "old", Version: 1, MaxTokens: 40, Status: adminapi.StatusActive}}}
	var m tea.Model = newModel(f)
	m = drive(m, func() tea.Msg { return detailMsg{iss: &f.issuers[0]} })
	m, _ = m.Update(key("e"))
	m = typeText(m, "1") // max_tokens 401
	m, _ = m.Update(key("enter"))
	if m.(model).screen != screenConfirm {
		t.Fatalf("expected confirm, got %v (err %q)", m.(model).screen, m.(model).err)
	}
	m, _ = m.Update(key("esc"))
	m, _ = m.Update(key("esc"))
	if m.(model).screen != screenDetail {
		t.Fatalf("esc from form went to %v, want detail", m.(model).screen)
	}
}

// Command letters typed into the filter must filter, not run.
func TestFilterTakesCommandLetters(t *testing.T) {
	f := &fakeAPI{issuers: []adminapi.Issuer{{ID: "1", Name: "quest", Version: 1}, {ID: "2", Name: "brave", Version: 1}}}
	var m tea.Model = newModel(f)
	m = drive(m, m.Init())
	m, _ = m.Update(key("/"))
	for _, r := range "quest" {
		var cmd tea.Cmd
		m, cmd = m.Update(key(string(r)))
		if cmd != nil {
			t.Fatalf("%q ran a command while filtering", r)
		}
	}
	if got := m.(model).visible(); len(got) != 1 || got[0].Name != "quest" {
		t.Fatalf("filter %q: %+v", m.(model).filter, got)
	}
}

func TestCreateFormRejectsCohortOverflow(t *testing.T) {
	m := newModel(&fakeAPI{}).openCreate()
	vals := []string{"x", "1", "70000", "40", "", "", "", "", ""}
	if _, err := m.form.build(m, vals); err == nil || !strings.Contains(err.Error(), "cohort") {
		t.Fatalf("cohort 70000 must be rejected, got %v", err)
	}
	vals[2] = ""
	if _, err := m.form.build(m, vals); err != nil {
		t.Fatalf("blank cohort must fall back to the server default, got %v", err)
	}
}

func retiringFake() *fakeAPI {
	stop := time.Now().Add(time.Hour)
	return &fakeAPI{issuers: []adminapi.Issuer{{ID: "1", Name: "old", Version: 1, Status: adminapi.StatusRetiring, StopIssuingAt: &stop}}}
}

// Postpone sends only after the typed confirmation, with the form's time.
func TestPostponeFlow(t *testing.T) {
	f := retiringFake()
	var m tea.Model = newModel(f)
	m = drive(m, func() tea.Msg { return detailMsg{iss: &f.issuers[0]} })
	m, _ = m.Update(key("p"))
	m, _ = m.Update(key("enter")) // default +30d
	m, _ = m.Update(key("enter")) // no typed name
	if f.postponed != nil {
		t.Fatal("postpone sent without typed confirmation")
	}
	confirmTyped(m, "old")
	if f.postponed == nil || f.postponed.StopIssuingAt.Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("postpone not sent with +30d: %+v", f.postponed)
	}
}

// Cancel applies only to a retiring issuer and needs the typed name.
func TestCancelRetirementFlow(t *testing.T) {
	f := retiringFake()
	var m tea.Model = newModel(f)
	m = drive(m, func() tea.Msg { return detailMsg{iss: &f.issuers[0]} })
	m, _ = m.Update(key("c"))
	confirmTyped(m, "old")
	if f.cancelled != "1" {
		t.Fatalf("cancel not sent: %q", f.cancelled)
	}

	active := adminapi.Issuer{ID: "2", Name: "a", Version: 1, Status: adminapi.StatusActive}
	m = drive(newModel(f), func() tea.Msg { return detailMsg{iss: &active} })
	m, _ = m.Update(key("c"))
	if m.(model).screen == screenConfirm {
		t.Fatal("cancel offered for an active issuer")
	}
}

// Esc back to the previous retire step must refocus its input.
func TestRetireWizardEscRefocusesStep(t *testing.T) {
	f, m := retireSetup()
	var tm tea.Model = m.openRetire(f.issuers[0])
	tm, _ = tm.Update(key("enter")) // step 1: stop issuing
	tm, _ = tm.Update(key("enter")) // step 2: stop redeeming
	tm, _ = tm.Update(key("esc"))   // back to step 1
	w := tm.(model).retire
	if w.step != 1 || !w.stopIssuing.Focused() || w.stopRedeeming.Focused() {
		t.Fatalf("step %d, stopIssuing focused %v, stopRedeeming focused %v", w.step, w.stopIssuing.Focused(), w.stopRedeeming.Focused())
	}
	tm = typeText(tm, "x")
	if got := tm.(model).retire.stopIssuing.Value(); got != "nowx" {
		t.Fatalf("stop issuing not editable after esc: %q", got)
	}
}

// retireSetup is a model listing two active issuers, "old" and "new".
func retireSetup() (*fakeAPI, model) {
	f := &fakeAPI{issuers: []adminapi.Issuer{
		{ID: "1", Name: "old", Version: 1, Status: adminapi.StatusActive},
		{ID: "2", Name: "new", Version: 1, Status: adminapi.StatusActive},
	}}
	m := newModel(f)
	m.issuers = f.issuers
	return f, m
}

// confirmTyped types name on the confirm screen, presses enter and runs the
// resulting command.
func confirmTyped(m tea.Model, name string) tea.Model {
	m = typeText(m, name)
	m, cmd := m.Update(key("enter"))
	return drive(m, cmd)
}

// A second enter before the reply must not send the mutation again.
func TestConfirmSendsOnce(t *testing.T) {
	f := retiringFake()
	var m tea.Model = newModel(f)
	m = drive(m, func() tea.Msg { return detailMsg{iss: &f.issuers[0]} })
	m, _ = m.Update(key("c"))
	m = typeText(m, "old")
	m, first := m.Update(key("enter"))
	_, second := m.Update(key("enter"))
	if first == nil || second != nil {
		t.Fatalf("first enter must send and the second must not: %v %v", first != nil, second != nil)
	}
}

// A blank max_tokens on the edit form leaves it unchanged.
func TestEditBlankMaxTokensUnchanged(t *testing.T) {
	exp := time.Now().Add(24 * time.Hour)
	m := newModel(&fakeAPI{}).openEdit(adminapi.Issuer{ID: "1", Name: "a", MaxTokens: 40, ExpiresAt: &exp})
	if _, err := m.form.build(m, []string{"", ""}); err == nil || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("blank fields must change nothing, got %v", err)
	}
	later := exp.Add(48 * time.Hour).UTC().Format(time.RFC3339)
	req, err := m.form.build(m, []string{"", later})
	if err != nil {
		t.Fatal(err)
	}
	if body := req.body.(adminapi.UpdateIssuerRequest); body.MaxTokens != nil || body.ExpiresAt == nil {
		t.Fatalf("only expires_at must change: %+v", body)
	}
}
