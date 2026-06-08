// proton-sync is a bidirectional sync daemon between ProtonMail contacts
// and a Synology CardDAV server.
//
// Commands:
//
//	proton-sync auth    – interactive bootstrap: SRP login + OTP + encrypted auth.json
//	proton-sync sync    – run one sync cycle and exit
//	proton-sync daemon  – run sync on an interval until SIGTERM
//
// All credentials are stored in auth.json, encrypted with AES-256-GCM
// derived from a generated bridge password (printed once at bootstrap).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/secbyd/proton-carddav/internal/auth"
	protonbridge "github.com/secbyd/proton-carddav/internal/proton"
	"github.com/secbyd/proton-carddav/internal/sync"
)

const defaultInterval = 5 * time.Minute

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "auth":
		cmdAuth()
	case "sync":
		cmdSync()
	case "daemon":
		cmdDaemon()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: proton-sync <auth|sync|daemon>")
	os.Exit(1)
}

// ───────────────────────────────────────────────────────────────────────────────

// cmdAuth runs the interactive bootstrap:
//  1. Prompt Proton + Synology credentials
//  2. Test Proton login (with OTP if needed)
//  3. Generate a bridge password
//  4. Encrypt and persist auth.json
func cmdAuth() {
	cfg, bridgePass, err := auth.Bootstrap()
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	if err := auth.Save("auth.json", cfg, bridgePass); err != nil {
		log.Fatalf("auth save: %v", err)
	}
	fmt.Println()
	fmt.Println("auth.json written. Your bridge password (store securely):")
	fmt.Println()
	fmt.Println(" ", bridgePass)
	fmt.Println()
	fmt.Println("Set BRIDGE_PASSWORD=<above> before running sync or daemon.")
}

// ───────────────────────────────────────────────────────────────────────────────

func cmdSync() {
	cfg := loadConfig()
	ctx := context.Background()

	engine, err := buildEngine(ctx, cfg)
	if err != nil {
		log.Fatalf("sync: build engine: %v", err)
	}
	defer engine.Close()

	if err := engine.SyncOnce(ctx); err != nil {
		log.Fatalf("sync: %v", err)
	}
}

// ───────────────────────────────────────────────────────────────────────────────

func cmdDaemon() {
	cfg := loadConfig()

	interval := defaultInterval
	if s := os.Getenv("SYNC_INTERVAL_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	engine, err := buildEngine(ctx, cfg)
	if err != nil {
		log.Fatalf("daemon: build engine: %v", err)
	}
	defer engine.Close()

	log.Printf("daemon: starting, sync interval %s", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on start.
	if err := engine.SyncOnce(ctx); err != nil {
		log.Printf("daemon: sync error: %v", err)
	}

	for {
		select {
		case <-ticker.C:
			if err := engine.SyncOnce(ctx); err != nil {
				log.Printf("daemon: sync error: %v", err)
			}
		case <-ctx.Done():
			log.Println("daemon: shutting down")
			return
		}
	}
}

// ───────────────────────────────────────────────────────────────────────────────

type appConfig struct {
	protonUsername string
	protonPassword string
	protonMboxPass string
	synologyURL     string
	synologyBook    string
	synologyUser    string
	synologyPass    string
	conflictPolicy  string
	bridgePass      string
	authFile        string
}

func loadConfig() *appConfig {
	// Prefer encrypted auth.json when BRIDGE_PASSWORD is set.
	bridgePass := os.Getenv("BRIDGE_PASSWORD")
	authFile := envOr("AUTH_FILE", "auth.json")

	if bridgePass != "" {
		cfg, err := auth.Load(authFile, bridgePass)
		if err != nil {
			log.Fatalf("load auth.json: %v", err)
		}
		return &appConfig{
			protonUsername: cfg.ProtonUsername,
			protonPassword: cfg.ProtonPassword,
			protonMboxPass: cfg.ProtonMboxPass,
			synologyURL:     cfg.SynologyURL,
			synologyBook:    cfg.SynologyAddressbookPath,
			synologyUser:    cfg.SynologyUsername,
			synologyPass:    cfg.SynologyPassword,
			conflictPolicy:  cfg.ConflictPolicy,
		}
	}

	// Fall back to environment variables.
	return &appConfig{
		protonUsername: mustEnv("PROTON_USERNAME"),
		protonPassword: mustEnv("PROTON_PASSWORD"),
		protonMboxPass: os.Getenv("PROTON_MBOX_PASSWORD"),
		synologyURL:     mustEnv("SYNOLOGY_CARDDAV_URL"),
		synologyBook:    mustEnv("SYNOLOGY_ADDRESSBOOK_PATH"),
		synologyUser:    mustEnv("SYNOLOGY_USERNAME"),
		synologyPass:    mustEnv("SYNOLOGY_PASSWORD"),
		conflictPolicy:  envOr("CONFLICT_POLICY", "duplicate"),
	}
}

// buildEngine authenticates with Proton (using NewClientAndBridge which
// handles SRP, OTP, salt derivation, and keyring unlock internally) and
// returns a ready Engine.
func buildEngine(ctx context.Context, cfg *appConfig) (*sync.Engine, error) {
	bridge, err := protonbridge.NewClientAndBridge(
		ctx,
		cfg.protonUsername,
		cfg.protonPassword,
		cfg.protonMboxPass,
		nil, // OTP not used in daemon mode; credentials from auth.json
	)
	if err != nil {
		return nil, fmt.Errorf("proton auth: %w", err)
	}

	return sync.NewEngine(bridge, cfg.synologyURL, cfg.synologyBook,
		cfg.synologyUser, cfg.synologyPass, cfg.conflictPolicy), nil
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
