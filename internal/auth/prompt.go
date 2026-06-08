package auth

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func prompt(label string, secret bool) string {
	fmt.Print(label)
	if secret {
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "read password: %v\n", err)
			os.Exit(1)
		}
		return strings.TrimSpace(string(b))
	}
	var s string
	fmt.Scanln(&s) //nolint:errcheck
	return strings.TrimSpace(s)
}
