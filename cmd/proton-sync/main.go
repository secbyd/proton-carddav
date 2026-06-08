// proton-sync: bidirectional sync daemon between ProtonMail Contacts and
// a Synology CardDAV server.
//
// Commands:
//
//	proton-sync auth     — interactive bootstrap: Proton login + OTP, Synology
//	                       credentials; writes encrypted auth.json
//	proton-sync sync     — sync once and exit
//	proton-sync daemon   — sync on a configurable interval forever
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/secbyd/proton-carddav/internal/auth"
	"github.com/secbyd/proton-carddav/internal/sync"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "auth":
		if err := auth.Bootstrap(); err != nil {
			log.Fatalf("auth: %v", err)
		}
		fmt.Println("auth.json written. Run 'proton-sync sync' to test.")

	case "sync":
		cfg, err := auth.Load()
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		ctx := context.Background()
		engine, err := sync.NewEngine(ctx, cfg)
		if err != nil {
			log.Fatalf("init sync engine: %v", err)
		}
		defer engine.Close()
		if err := engine.SyncOnce(ctx); err != nil {
			log.Fatalf("sync: %v", err)
		}
		fmt.Println("sync complete.")

	case "daemon":
		cfg, err := auth.Load()
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		engine, err := sync.NewEngine(ctx, cfg)
		if err != nil {
			log.Fatalf("init sync engine: %v", err)
		}
		defer engine.Close()

		interval := time.Duration(cfg.SyncIntervalSec) * time.Second
		if interval < 30*time.Second {
			interval = 5 * time.Minute
		}
		log.Printf("daemon: syncing every %s (Ctrl+C to stop)", interval)
		for {
			if err := engine.SyncOnce(ctx); err != nil {
				log.Printf("sync error: %v", err)
			}
			select {
			case <-ctx.Done():
				log.Println("daemon: shutting down")
				return
			case <-time.After(interval):
			}
		}

	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: proton-sync <command>

Commands:
  auth    Interactive setup: authenticate with ProtonMail (+ OTP) and Synology,
          generate bridge password, write encrypted auth.json
  sync    Run one bidirectional sync and exit
  daemon  Run bidirectional sync on a loop (interval set in auth.json)

Config file: auth.json (AES-256-GCM encrypted, key = bridge password)
`)
}
