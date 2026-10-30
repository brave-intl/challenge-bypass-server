// cbp-manage is the operator TUI for challenge-bypass-server issuers.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/brave-intl/challenge-bypass-server/adminapi"
)

func main() {
	url := flag.String("url", os.Getenv("CBP_ADMIN_URL"), "server base URL (env CBP_ADMIN_URL)")
	keyPath := flag.String("private-key", os.Getenv("CBP_ADMIN_PRIVATE_KEY"), "OpenSSH ed25519 private key (env CBP_ADMIN_PRIVATE_KEY)")
	whoami := flag.Bool("whoami", false, "print the operator this key is authorized as, then exit")
	flag.Parse()
	if *url == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "cbp-manage: --url and --private-key (or CBP_ADMIN_URL / CBP_ADMIN_PRIVATE_KEY) are required")
		os.Exit(2)
	}
	key, err := adminapi.LoadPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cbp-manage:", err)
		os.Exit(1)
	}
	client := &adminapi.Client{BaseURL: *url, Key: key}
	if *whoami {
		op, err := client.WhoAmI(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "cbp-manage:", describeErr(err))
			os.Exit(1)
		}
		fmt.Println(op)
		return
	}
	if _, err := tea.NewProgram(newModel(client), tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "cbp-manage:", err)
		os.Exit(1)
	}
}
