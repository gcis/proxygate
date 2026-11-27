package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/gcis/proxygate/internal/auth"
)

// runAdminCommand handles the maintenance subcommands. They work on the
// files next to the config, so anyone who can act as the service user (or
// root) can recover access; see docs/security.md.
func runAdminCommand(args []string, stdin *os.File, stdout, stderr io.Writer) (handled bool, code int) {
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case "passwd":
		return true, runPasswd(args[1:], stdin, stdout, stderr)
	case "token":
		return true, runToken(args[1:], stdout, stderr)
	}
	return false, 0
}

func authStoreFor(configPath string) (*auth.Store, string, error) {
	dir := filepath.Dir(configPath)
	if _, err := os.Stat(dir); err != nil {
		return nil, "", fmt.Errorf("config directory %s: %w", dir, err)
	}
	return auth.NewStore(dir), dir, nil
}

func runPasswd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "./data/proxygate.json", "Path to config file")
	generate := fs.Bool("generate", false, "Generate a random password and print it")
	policy := fs.String("policy", "", `Password rules: "strong" (12+ characters, no common passwords) or "basic" (8+). Default: keep the current setting`)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: proxygate passwd [--config path] [--generate] [--policy strong|basic]")
		fmt.Fprintln(fs.Output(), "Sets the admin password and signs out every admin session.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var strong *bool
	switch *policy {
	case "":
	case "strong", "basic":
		v := *policy == "strong"
		strong = &v
	default:
		fmt.Fprintln(stderr, `--policy must be "strong" or "basic"`)
		return 2
	}

	store, dir, err := authStoreFor(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	var password string
	if *generate {
		if password, err = auth.RandomPassword(); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
	} else if password, err = readNewPassword(stdin, stderr); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	if err := store.SetPassword(password, strong); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	matchOwnership(*configPath, filepath.Join(dir, auth.AuthFileName))

	if *generate {
		fmt.Fprintln(stdout, password)
		fmt.Fprintln(stderr, "Admin password set to the value above. All admin sessions are signed out.")
	} else {
		fmt.Fprintln(stdout, "Admin password updated. All admin sessions are signed out.")
	}
	return 0
}

// readNewPassword prompts twice without echo on a terminal, or reads one
// line from stdin when piped (for automation).
func readNewPassword(stdin *os.File, stderr io.Writer) (string, error) {
	fd := int(stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return "", errors.New("no password on stdin")
		}
		return pw, nil
	}
	fmt.Fprint(stderr, "New admin password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(stderr, "Repeat password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}
	return string(first), nil
}

func runToken(args []string, stdout, stderr io.Writer) int {
	usage := func() {
		fmt.Fprintln(stderr, "usage: proxygate token create|list|revoke [name] [--config path]")
		fmt.Fprintln(stderr, "API tokens authenticate scripts with: Authorization: Bearer <token>")
	}
	if len(args) == 0 {
		usage()
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "./data/proxygate.json", "Path to config file")
	// Allow the name before or after the flags.
	var name string
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		name, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if name == "" && fs.NArg() > 0 {
		name = fs.Arg(0)
	}

	store, dir, err := authStoreFor(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	switch action {
	case "create":
		if name == "" {
			usage()
			return 2
		}
		secret, err := store.CreateToken(name)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		matchOwnership(*configPath, filepath.Join(dir, auth.AuthFileName))
		fmt.Fprintln(stdout, secret)
		fmt.Fprintf(stderr, "Token %q created. It is shown only once; store it somewhere safe.\n", name)
	case "list":
		tokens, err := store.Tokens()
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		if len(tokens) == 0 {
			fmt.Fprintln(stdout, "No API tokens.")
		}
		for _, t := range tokens {
			fmt.Fprintf(stdout, "%s\tcreated %s\n", t.Name, t.CreatedAt)
		}
	case "revoke":
		if name == "" {
			usage()
			return 2
		}
		if err := store.RevokeToken(name); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		fmt.Fprintf(stdout, "Token %q revoked.\n", name)
	default:
		usage()
		return 2
	}
	return 0
}
