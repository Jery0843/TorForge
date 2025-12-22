// Package ui provides the TUI dashboard for TorForge
package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7D56F4")).
			Background(lipgloss.Color("#1a1a2e")).
			Padding(0, 1)

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575")).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6B6B")).
			Bold(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	highlightStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFD700"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA"))
)

// KeyMap defines keyboard shortcuts
type KeyMap struct {
	Quit       key.Binding
	NewCircuit key.Binding
	Refresh    key.Binding
	Tab        key.Binding
	Help       key.Binding
}

var keys = KeyMap{
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	NewCircuit: key.NewBinding(
		key.WithKeys("n"),
		key.WithHelp("n", "new circuit"),
	),
	Refresh: key.NewBinding(
		key.WithKeys("r"),
		key.WithHelp("r", "refresh"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "switch view"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
}

func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Quit}
}

func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.NewCircuit, k.Refresh, k.Tab},
		{k.Quit, k.Help},
	}
}

// Stats represents the current proxy stats
type Stats struct {
	Running        bool
	Uptime         time.Duration
	ExitIP         string
	ActiveCircuits int
	BytesSent      int64
	BytesRecv      int64
	DNSQueries     int64
	BlockedLeaks   int
	Latency        time.Duration
}

// Circuit represents a Tor circuit for display
type Circuit struct {
	ID        string
	Status    string
	Age       time.Duration
	Bandwidth string
	ExitNode  string
}

// Model is the Bubble Tea model for the dashboard
type Model struct {
	stats        Stats
	circuits     []Circuit
	_connections []Connection // Reserved for active connection display
	logs         []string
	spinner      spinner.Model
	table        table.Model
	help         help.Model
	keys         KeyMap
	width        int
	height       int
	currentTab   int
	showHelp     bool
	lastUpdate   time.Time

	// Channels for updates
	updateCh  chan Stats
	circuitCh chan []Circuit
	logCh     chan string
}

// Connection represents an active connection
type Connection struct {
	Source      string
	Destination string
	Protocol    string
	Status      string
	Circuit     string
}

// NewModel creates a new dashboard model
func NewModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))

	columns := []table.Column{
		{Title: "ID", Width: 8},
		{Title: "Status", Width: 10},
		{Title: "Age", Width: 10},
		{Title: "Bandwidth", Width: 12},
		{Title: "Exit Node", Width: 20},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(5),
	)

	tableStyle := table.DefaultStyles()
	tableStyle.Header = tableStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#7D56F4")).
		BorderBottom(true).
		Bold(true)
	tableStyle.Selected = tableStyle.Selected.
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#7D56F4")).
		Bold(true)
	t.SetStyles(tableStyle)

	return Model{
		spinner:    s,
		table:      t,
		help:       help.New(),
		keys:       keys,
		updateCh:   make(chan Stats, 10),
		circuitCh:  make(chan []Circuit, 10),
		logCh:      make(chan string, 100),
		lastUpdate: time.Now(),
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type tickMsg time.Time

// Update handles messages
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Help):
			m.showHelp = !m.showHelp
		case key.Matches(msg, m.keys.Tab):
			m.currentTab = (m.currentTab + 1) % 3
		case key.Matches(msg, m.keys.NewCircuit):
			// Trigger new circuit request
			cmds = append(cmds, func() tea.Msg {
				return newCircuitMsg{}
			})
		case key.Matches(msg, m.keys.Refresh):
			m.lastUpdate = time.Now()
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.Width = msg.Width

	case tickMsg:
		m.lastUpdate = time.Time(msg)
		cmds = append(cmds, tickCmd())

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case statsMsg:
		m.stats = Stats(msg)

	case circuitsMsg:
		m.circuits = []Circuit(msg)
		m.updateTable()
	}

	return m, tea.Batch(cmds...)
}

type newCircuitMsg struct{}
type statsMsg Stats
type circuitsMsg []Circuit

func (m *Model) updateTable() {
	rows := make([]table.Row, len(m.circuits))
	for i, c := range m.circuits {
		rows[i] = table.Row{
			c.ID,
			c.Status,
			formatDuration(c.Age),
			c.Bandwidth,
			c.ExitNode,
		}
	}
	m.table.SetRows(rows)
}

// View renders the dashboard
func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	var b strings.Builder

	// Header
	header := m.renderHeader()
	b.WriteString(header)
	b.WriteString("\n\n")

	// Main content based on tab
	switch m.currentTab {
	case 0:
		b.WriteString(m.renderOverview())
	case 1:
		b.WriteString(m.renderCircuits())
	case 2:
		b.WriteString(m.renderLogs())
	}

	b.WriteString("\n")

	// Help
	if m.showHelp {
		b.WriteString(m.help.View(m.keys))
	} else {
		b.WriteString(dimStyle.Render("Press ? for help"))
	}

	return b.String()
}

func (m Model) renderHeader() string {
	// Title
	title := titleStyle.Render("🧅 TorForge")

	// Status indicator
	var status string
	if m.stats.Running {
		status = statusStyle.Render("● ACTIVE")
	} else {
		status = errorStyle.Render("○ INACTIVE")
	}

	// Tabs
	tabs := []string{"Overview", "Circuits", "Logs"}
	var tabViews []string
	for i, t := range tabs {
		if i == m.currentTab {
			tabViews = append(tabViews, highlightStyle.Render("["+t+"]"))
		} else {
			tabViews = append(tabViews, dimStyle.Render(" "+t+" "))
		}
	}
	tabBar := strings.Join(tabViews, " ")

	// Combine
	left := title + " " + status
	right := tabBar

	padding := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if padding < 0 {
		padding = 0
	}

	return left + strings.Repeat(" ", padding) + right
}

func (m Model) renderOverview() string {
	// Stats boxes
	boxes := []string{
		m.renderStatBox("Exit IP", m.stats.ExitIP, "🌐"),
		m.renderStatBox("Circuits", fmt.Sprintf("%d active", m.stats.ActiveCircuits), "🔗"),
		m.renderStatBox("Uptime", formatDuration(m.stats.Uptime), "⏱"),
		m.renderStatBox("Latency", fmt.Sprintf("%dms", m.stats.Latency.Milliseconds()), "📊"),
	}

	row1 := lipgloss.JoinHorizontal(lipgloss.Top, boxes[0], " ", boxes[1])
	row2 := lipgloss.JoinHorizontal(lipgloss.Top, boxes[2], " ", boxes[3])

	statsSection := lipgloss.JoinVertical(lipgloss.Left, row1, row2)

	// Traffic stats
	trafficBox := boxStyle.Render(
		headerStyle.Render("Traffic") + "\n" +
			fmt.Sprintf("↑ Sent:     %s\n", formatBytes(m.stats.BytesSent)) +
			fmt.Sprintf("↓ Received: %s\n", formatBytes(m.stats.BytesRecv)) +
			fmt.Sprintf("🔍 DNS:     %d queries\n", m.stats.DNSQueries) +
			fmt.Sprintf("🛡 Blocked:  %d leaks", m.stats.BlockedLeaks),
	)

	return lipgloss.JoinHorizontal(lipgloss.Top, statsSection, "  ", trafficBox)
}

func (m Model) renderStatBox(title, value, icon string) string {
	content := fmt.Sprintf("%s %s\n%s", icon, headerStyle.Render(title), highlightStyle.Render(value))
	return boxStyle.Width(20).Render(content)
}

func (m Model) renderCircuits() string {
	if len(m.circuits) == 0 {
		return boxStyle.Render(
			headerStyle.Render("Circuits") + "\n\n" +
				dimStyle.Render("No active circuits") + "\n" +
				m.spinner.View() + " Waiting for Tor...",
		)
	}

	return boxStyle.Width(m.width - 4).Render(
		headerStyle.Render("Active Circuits") + "\n\n" +
			m.table.View(),
	)
}

func (m Model) renderLogs() string {
	var logLines string
	maxLogs := 10
	start := 0
	if len(m.logs) > maxLogs {
		start = len(m.logs) - maxLogs
	}

	for _, log := range m.logs[start:] {
		logLines += log + "\n"
	}

	if logLines == "" {
		logLines = dimStyle.Render("No recent logs")
	}

	return boxStyle.Width(m.width - 4).Render(
		headerStyle.Render("Recent Logs") + "\n\n" + logLines,
	)
}

// UpdateStats sends updated stats to the model
func (m *Model) UpdateStats(stats Stats) {
	select {
	case m.updateCh <- stats:
	default:
	}
}

// UpdateCircuits sends updated circuit list to the model
func (m *Model) UpdateCircuits(circuits []Circuit) {
	select {
	case m.circuitCh <- circuits:
	default:
	}
}

// AddLog adds a log entry
func (m *Model) AddLog(msg string) {
	timestamp := time.Now().Format("15:04:05")
	entry := dimStyle.Render(timestamp) + " " + msg

	m.logs = append(m.logs, entry)
	if len(m.logs) > 1000 {
		m.logs = m.logs[100:]
	}
}

// Helper functions
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// RunDashboard starts the TUI dashboard
func RunDashboard() error {
	p := tea.NewProgram(
		NewModel(),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	_, err := p.Run()
	return err
}
