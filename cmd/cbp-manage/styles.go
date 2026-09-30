package main

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Padding(0, 1)
	helpStyle   = lipgloss.NewStyle().Faint(true)
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	statusStyle = map[adminapi.Status]lipgloss.Style{
		adminapi.StatusActive:   lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
		adminapi.StatusRetiring: lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		adminapi.StatusRetired:  lipgloss.NewStyle().Foreground(lipgloss.Color("208")),
		adminapi.StatusExpired:  lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}
)

func statusText(s adminapi.Status) string { return statusStyle[s].Render(string(s)) }
