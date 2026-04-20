package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	fs := flag.NewFlagSet("main", flag.ExitOnError)

	quiet := false
	fs.BoolVar(&quiet, "quiet", false, "suppress non-error log output")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse flags: %v\n", err)
		os.Exit(2)
	}

	cmd := fs.Arg(0)
	args := fs.Args()[1:]

	opts := &slog.HandlerOptions{}
	if quiet {
		opts.Level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, opts)))

	var err error
	switch cmd {
	case "relay":
		err = runRelay(args)
	case "server":
		err = runServer(args)
	case "client":
		err = runClient(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		slog.Error("exited with error", "app", cmd, "error", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [--queit] <command> [flags]

Commands:
  relay    Run the rendezvous relay.
  server   Expose a local TCP service through a relay.
  client   Connect to a service via a relay and bridge it to stdin/stdout.

Run "%s <command> -h" for command-specific flags.
`, os.Args[0], os.Args[0])
}

func runRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)

	authToken := ""
	fs.StringVar(&authToken, "auth-token", "", "authentication token for clients and servers (optional)")
	port := 0
	fs.IntVar(&port, "port", 0, "TCP/UDP port the relay listens on (shorthand)")
	punchServerAddress := ""
	fs.StringVar(&punchServerAddress, "punch-server-address", "", "address of the punch server to use for NAT traversal")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if port == 0 {
		return fmt.Errorf("-port is required")
	}
	if punchServerAddress == "" {
		return fmt.Errorf("-punch-server-address is required")
	}

	slog.Info("starting relay", "port", port, "punch_server_address", punchServerAddress)

	NewRelay(authToken, port, punchServerAddress).Start()

	return nil
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)

	relay := ""
	fs.StringVar(&relay, "relay", "", "relay url (required)")
	authToken := ""
	fs.StringVar(&authToken, "auth-token", "", "authentication token for the relay (optional)")
	id := ""
	fs.StringVar(&id, "id", "", "service id advertised to the relay (required)")
	forward := ""
	fs.StringVar(&forward, "forward", "", "address to forward connections to (required)")

	err := fs.Parse(args)
	if err != nil {
		return err
	}

	if id == "" {
		return fmt.Errorf("-id is required")
	}
	if relay == "" {
		return fmt.Errorf("-relay is required")
	}
	if forward == "" {
		return fmt.Errorf("-forward is required")
	}

	fwdAddr, err := net.ResolveTCPAddr("tcp", forward)
	if err != nil {
		return fmt.Errorf("invalid forward address %q: %w", forward, err)
	}

	slog.Info("starting server", "relay", relay, "id", id, "forward", fwdAddr.String())

	srv, err := NewServer(relay, authToken, id, fwdAddr)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	err = srv.Start()
	if err != nil {
		return fmt.Errorf("server exited: %w", err)
	}

	return nil
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)

	relayURL := ""
	fs.StringVar(&relayURL, "relay", "", "relay url (required)")
	authToken := ""
	fs.StringVar(&authToken, "auth-token", "", "authentication token for the relay (optional)")
	id := ""
	fs.StringVar(&id, "id", "", "service id to connect to (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if relayURL == "" {
		return fmt.Errorf("-relay is required")
	}
	if id == "" {
		return fmt.Errorf("-id is required")
	}

	slog.Info("starting client", "relay", relayURL, "id", id)

	cli, err := NewClient(relayURL, authToken, id)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	if err := cli.Start(context.Background()); err != nil {
		return fmt.Errorf("client error: %w", err)
	}
	return nil
}
