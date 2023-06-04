package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/sys"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/term"
)

func PrintStartupMessage(node *kes.Server) {
	var faint, item tui.Style
	if term.IsTerminal(int(os.Stdout.Fd())) {
		faint = faint.Faint(true)
		item = item.Foreground(tui.Color("#2e42d1")).Bold(true)
	}

	state := node.State()
	ids := maps.Keys(state.Cluster)
	slices.Sort(ids)

	buffer := new(Buffer)
	buffer.Stylef(item, "%-12s", "Copyright").Sprintf("%-22s", "MinIO, Inc.").Styleln(faint, "https://min.io")
	buffer.Stylef(item, "%-12s", "License").Sprintf("%-22s", "GNU AGPLv3").Styleln(faint, "https://www.gnu.org/licenses/agpl-3.0.html")
	buffer.Stylef(item, "%-12s", "Version").Sprintf("%-22s", sys.BinaryInfo().Version).Stylef(faint, "%s/%s\n", runtime.GOOS, runtime.GOARCH)
	buffer.Sprintln()

	buffer.Stylef(item, "%-12s", "Cluster").Styleln(faint, "Node   Address")
	for _, id := range ids {
		buffer.Sprintf("%-12s%-6s %s", " ", "["+strconv.Itoa(id)+"]", state.Cluster[id])
		if id == state.ID {
			buffer.Stylef(item, "  ●")
		}
		buffer.Sprintln()
	}
	buffer.Sprintln()

	admin := state.Admin
	if admin.IsUnknown() {
		admin = state.APIKey.Identity()
	}

	buffer.Stylef(item, "%-12s", "Admin")
	if r, err := hex.DecodeString(admin.String()); err == nil && len(r) == sha256.Size {
		buffer.Sprintln(admin)
	} else {
		buffer.Sprintf("%-22s", "_").Styleln(faint, "[ disabled ]")
	}
	if admin == state.APIKey.Identity() {
		buffer.Stylef(item, "%-12s", "API Key").Sprintln(state.APIKey.String())
	}
	buffer.Sprintln()

	buffer.Stylef(item, "%-12s", "Docs").Sprintln("<link-to-docs>")
	buffer.Stylef(item, "%-12s", "CLI Access").Sprintf("$ export KES_SERVER=https://%s", state.Addr).Sprintln()
	if admin == state.APIKey.Identity() {
		buffer.Sprintf("%-12s$ export KES_API_KEY=%s", " ", state.APIKey.String()).Sprintln()
	}
	buffer.Sprintf("%-12s$ kes --help", " ")

	fmt.Println(buffer.String())
}
