package studio

import (
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/abdul-hamid-achik/tinyvault/internal/agent"
	"github.com/abdul-hamid-achik/tinyvault/internal/service"
)

// serviceProbeTimeout bounds the agent dial. The studio must stay responsive,
// so a wedged agent shows as "not running" rather than freezing a pane.
const serviceProbeTimeout = 500 * time.Millisecond

// serviceData is what the status pane shows about the agent and its managed
// service. Every field is derived from a read: dialing the agent's socket for
// metadata, stat-ing the service definition, and asking the service manager
// whether it is registered. Nothing here writes, installs, or unlocks — the
// studio stays read-only by default, and installing a system service belongs in
// `tvault agent install`, not behind a keystroke in a browser.
type serviceData struct {
	// probed distinguishes "not loaded yet" from "loaded and found nothing",
	// so the pane can stay quiet until the first probe returns.
	probed bool

	agentRunning bool
	agentPID     int
	// agentIdleRemaining is seconds until the agent auto-locks; 0 when it never
	// will or is not running.
	agentIdleRemaining int

	// serviceKind is "launchd" or "systemd", empty when the platform has
	// neither or no definition is installed.
	serviceKind string
	// serviceRegistered reports whether the manager currently knows the service,
	// which differs from a definition merely existing on disk.
	serviceRegistered bool
}

type serviceLoadedMsg serviceData

// serviceCmd probes the agent and the installed service.
//
// It never returns an error message: none of this is the question the studio
// exists to answer, so a missing agent, an absent launchctl, or an unsupported
// platform all read as "nothing to report" rather than an error banner over the
// user's secrets.
func serviceCmd(dir string) tea.Cmd {
	return func() tea.Msg {
		sd := serviceData{probed: true}

		if c, err := agent.Dial(dir, serviceProbeTimeout); err == nil {
			if st, serr := c.Status(); serr == nil {
				sd.agentRunning = true
				sd.agentPID = st.PID
				sd.agentIdleRemaining = st.IdleRemainingSeconds
			}
		}

		kind, err := service.DefaultKind()
		if err != nil {
			// No launchd and no systemd user units: leave serviceKind empty.
			return serviceLoadedMsg(sd)
		}
		installed, _, err := service.Installed(kind)
		if err != nil || !installed {
			return serviceLoadedMsg(sd)
		}
		sd.serviceKind = string(kind)
		if registered, lerr := service.Loaded(kind); lerr == nil {
			sd.serviceRegistered = registered
		}
		return serviceLoadedMsg(sd)
	}
}
