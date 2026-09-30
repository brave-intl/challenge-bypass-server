package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

type api interface {
	ListIssuers(context.Context) ([]adminapi.Issuer, error)
	GetIssuer(context.Context, string) (*adminapi.Issuer, error)
	CreateIssuer(context.Context, adminapi.CreateIssuerRequest) (*adminapi.Issuer, error)
	UpdateIssuer(context.Context, string, adminapi.UpdateIssuerRequest) (*adminapi.Issuer, error)
	RetireIssuer(context.Context, string, adminapi.RetireRequest) (*adminapi.Issuer, error)
	CancelRetirement(context.Context, string) (*adminapi.Issuer, error)
	PostponeRetirement(context.Context, string, adminapi.PostponeRequest) (*adminapi.Issuer, error)
	ListAudit(context.Context, string, int) ([]adminapi.AuditEntry, error)
}

type screen int

const (
	screenList screen = iota
	screenDetail
	screenCreate
	screenEdit
	screenRetire
	screenConfirm
)

// messages
type issuersMsg []adminapi.Issuer
type detailMsg struct {
	iss   *adminapi.Issuer
	audit []adminapi.AuditEntry
}
type doneMsg struct {
	iss  *adminapi.Issuer
	note string
}
type errMsg struct{ err error }

// confirmReq is a pending mutation shown verbatim before it is sent.
type confirmReq struct {
	title         string
	body          any
	typeToConfirm string // non-empty: operator must type this exactly
	run           func() tea.Cmd
}

type model struct {
	api          api
	screen       screen
	issuers      []adminapi.Issuer
	table        table.Model
	filter       string
	cur          *adminapi.Issuer
	audit        []adminapi.AuditEntry
	err          string
	note         string
	confirm      *confirmReq
	confirmInput textinput.Model
	form         form         // Task 9
	retire       retireWizard // Task 9
	back         screen
	width        int
}

func newModel(c api) model {
	t := table.New(table.WithColumns([]table.Column{
		{Title: "Name", Width: 32}, {Title: "V", Width: 2}, {Title: "Cohort", Width: 6},
		{Title: "Status", Width: 9}, {Title: "Expires", Width: 17}, {Title: "Stop issuing", Width: 17},
	}), table.WithFocused(true), table.WithHeight(20))
	ti := textinput.New()
	ti.Placeholder = "type the issuer name to confirm"
	return model{api: c, table: t, confirmInput: ti}
}

func (m model) Init() tea.Cmd { return m.loadList() }

func (m model) loadList() tea.Cmd {
	return func() tea.Msg {
		l, err := m.api.ListIssuers(context.Background())
		if err != nil {
			return errMsg{err}
		}
		return issuersMsg(l)
	}
}

func (m model) loadDetail(id string) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		iss, err := m.api.GetIssuer(ctx, id)
		if err != nil {
			return errMsg{err}
		}
		audit, err := m.api.ListAudit(ctx, id, 20)
		if err != nil {
			return errMsg{err}
		}
		return detailMsg{iss, audit}
	}
}

// describeErr turns API errors into operator-facing text.
func describeErr(err error) string {
	var ae *adminapi.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case 401:
			return "request was not signed (401)"
		case 403:
			return "signature rejected (403): your key is not on the operator allowlist for this environment, or the request was altered in transit"
		case 408, 425:
			return fmt.Sprintf("request date rejected (%d): your clock is more than 10 minutes off the server's; sync it (e.g. `timedatectl` / `sntp`)", ae.Status)
		}
		return fmt.Sprintf("%d: %s", ae.Status, ae.Message)
	}
	return err.Error()
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func (m *model) rebuildTable() {
	rows := []table.Row{}
	for _, i := range m.visible() {
		rows = append(rows, table.Row{i.Name, fmt.Sprint(i.Version), fmt.Sprint(i.Cohort),
			string(i.Status), fmtTime(i.ExpiresAt), fmtTime(i.StopIssuingAt)})
	}
	m.table.SetRows(rows)
}

func (m model) visible() []adminapi.Issuer {
	if m.filter == "" {
		return m.issuers
	}
	out := []adminapi.Issuer{}
	for _, i := range m.issuers {
		if strings.Contains(strings.ToLower(i.Name), strings.ToLower(m.filter)) {
			out = append(out, i)
		}
	}
	return out
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.table.SetHeight(max(5, msg.Height-8))
		return m, nil
	case issuersMsg:
		m.issuers, m.err = msg, ""
		m.rebuildTable()
		return m, nil
	case detailMsg:
		m.cur, m.audit, m.err, m.screen = msg.iss, msg.audit, "", screenDetail
		return m, nil
	case doneMsg:
		m.note, m.err, m.confirm = msg.note, "", nil
		return m, tea.Batch(m.loadList(), m.loadDetail(msg.iss.ID))
	case errMsg:
		m.err = describeErr(msg.err)
		if m.screen == screenConfirm {
			m.screen, m.confirm = m.back, nil
		}
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	switch m.screen {
	case screenList:
		return m.updateList(msg)
	case screenDetail:
		return m.updateDetail(msg)
	case screenConfirm:
		return m.updateConfirm(msg)
	case screenCreate, screenEdit:
		return m.updateForm(msg) // Task 9
	case screenRetire:
		return m.updateRetire(msg) // Task 9
	}
	return m, nil
}

func (m model) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "q":
		return m, tea.Quit
	case "r":
		return m, m.loadList()
	case "n":
		return m.openCreate(), nil // Task 9
	case "enter":
		v := m.visible()
		if i := m.table.Cursor(); i >= 0 && i < len(v) {
			return m, m.loadDetail(v[i].ID)
		}
		return m, nil
	case "backspace":
		if m.filter != "" {
			m.filter = m.filter[:len(m.filter)-1]
			m.rebuildTable()
		}
		return m, nil
	case "up", "down", "k", "j", "pgup", "pgdown", "home", "end":
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		return m, cmd
	}
	if k.Type == tea.KeyRunes && k.String() != "/" {
		m.filter += string(k.Runes)
		m.rebuildTable()
	}
	return m, nil
}

func (m model) updateDetail(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok || m.cur == nil {
		return m, nil
	}
	cur := *m.cur
	switch k.String() {
	case "esc", "q":
		m.screen, m.note = screenList, ""
		return m, m.loadList()
	case "e":
		return m.openEdit(cur), nil // Task 9
	case "R":
		return m.openRetire(cur), nil // Task 9
	case "p":
		if cur.StopIssuingAt == nil || cur.Status == adminapi.StatusExpired {
			m.err = "postpone applies to a retiring or retired issuer"
			return m, nil
		}
		return m.openPostpone(cur), nil // Task 9
	case "c":
		if cur.Status != adminapi.StatusRetiring {
			m.err = "only a retiring issuer can have its retirement cancelled"
			return m, nil
		}
		return m.askConfirm(screenDetail, confirmReq{
			title:         "Cancel retirement of " + cur.Name,
			body:          map[string]string{"DELETE": "/v1/admin/issuers/" + cur.ID + "/retire"},
			typeToConfirm: cur.Name,
			run: func() tea.Cmd {
				return func() tea.Msg {
					iss, err := m.api.CancelRetirement(context.Background(), cur.ID)
					if err != nil {
						return errMsg{err}
					}
					return doneMsg{iss, "retirement cancelled"}
				}
			},
		}), nil
	}
	return m, nil
}

func (m model) askConfirm(back screen, req confirmReq) model {
	m.back, m.screen, m.confirm, m.err = back, screenConfirm, &req, ""
	m.confirmInput.SetValue("")
	if req.typeToConfirm != "" {
		m.confirmInput.Focus()
	}
	return m
}

func (m model) updateConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "esc":
		m.screen, m.confirm = m.back, nil
		return m, nil
	case "enter":
		if m.confirm.typeToConfirm != "" && m.confirmInput.Value() != m.confirm.typeToConfirm {
			m.err = "typed name does not match"
			return m, nil
		}
		return m, m.confirm.run()
	}
	if m.confirm.typeToConfirm != "" {
		var cmd tea.Cmd
		m.confirmInput, cmd = m.confirmInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder
	switch m.screen {
	case screenList:
		b.WriteString(titleStyle.Render("Issuers") + "  filter: " + m.filter + "\n")
		b.WriteString(m.table.View() + "\n")
		b.WriteString(helpStyle.Render("enter open · type to filter · n new · r refresh · q quit"))
	case screenDetail:
		b.WriteString(m.detailView())
	case screenConfirm:
		body, _ := json.MarshalIndent(m.confirm.body, "", "  ")
		b.WriteString(titleStyle.Render(m.confirm.title) + "\n\n" + string(body) + "\n\n")
		if m.confirm.typeToConfirm != "" {
			b.WriteString("Type " + m.confirm.typeToConfirm + " to confirm:\n" + m.confirmInput.View() + "\n")
		}
		b.WriteString(helpStyle.Render("enter send · esc back"))
	case screenCreate, screenEdit:
		b.WriteString(m.formView()) // Task 9
	case screenRetire:
		b.WriteString(m.retireView()) // Task 9
	}
	if m.note != "" {
		b.WriteString("\n" + okStyle.Render(m.note))
	}
	if m.err != "" {
		b.WriteString("\n" + errStyle.Render(m.err))
	}
	return b.String()
}

func (m model) detailView() string {
	i := m.cur
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n\n", titleStyle.Render(i.Name), statusText(i.Status))
	fmt.Fprintf(&b, "id            %s\nversion       %d   cohort %d   max_tokens %d\n", i.ID, i.Version, i.Cohort, i.MaxTokens)
	if i.Version >= 3 {
		d := "—"
		if i.Duration != nil {
			d = *i.Duration
		}
		fmt.Fprintf(&b, "duration      %s   buffer %d   overlap %d\n", d, i.Buffer, i.Overlap)
	}
	fmt.Fprintf(&b, "created       %s\nvalid from    %s\nexpires       %s   (stops redeeming)\n",
		fmtTime(i.CreatedAt), fmtTime(i.ValidFrom), fmtTime(i.ExpiresAt))
	if i.StopIssuingAt != nil {
		by := ""
		if i.RetiredBy != nil {
			by = " by " + *i.RetiredBy
		}
		fmt.Fprintf(&b, "stop issuing  %s%s\nreplaced by   %s\n", fmtTime(i.StopIssuingAt), by, m.nameOf(i.ReplacementID))
	}
	for _, r := range i.Replaces {
		fmt.Fprintf(&b, "replaces      %s\n", m.nameOf(&r))
	}
	fmt.Fprintf(&b, "\nkeys (%d)\n", len(i.Keys))
	for _, k := range i.Keys {
		pk := k.PublicKey
		if len(pk) > 16 {
			pk = pk[:16] + "…"
		}
		fmt.Fprintf(&b, "  %s  %s → %s\n", pk, fmtTime(k.StartAt), fmtTime(k.EndAt))
	}
	b.WriteString("\naudit\n")
	for _, a := range m.audit {
		fmt.Fprintf(&b, "  %s  %-14s %s\n", a.CreatedAt.UTC().Format("2006-01-02 15:04Z"), a.Action, a.Operator)
	}
	b.WriteString("\n" + helpStyle.Render("e edit · R replace/retire · c cancel retirement · p postpone stop-issuing · esc back"))
	return b.String()
}

func (m model) nameOf(id *string) string {
	if id == nil {
		return "—"
	}
	for _, i := range m.issuers {
		if i.ID == *id {
			return i.Name + " (" + *id + ")"
		}
	}
	return *id
}
