// proton-carddav is a single-user RFC 6352 CardDAV bridge for ProtonMail.
//
// # Modes
//
//	proton-carddav auth    — interactive first-time setup; writes auth.json
//	proton-carddav serve   — start the CardDAV HTTP server (default when no arg)
//
// # Environment variables (serve mode, alternative to auth.json)
//
//	PROTON_USERNAME          ProtonMail account username
//	PROTON_PASSWORD          ProtonMail account password
//	PROTON_MBOX_PASSWORD     Mailbox password (two-password mode only; omit otherwise)
//	PROTON_TOTP              TOTP code for 2FA (non-interactive daemon mode)
//	BRIDGE_PASSWORD          Bridge password to decrypt auth.json (preferred over above)
//	CARDDAV_BASE_URL         Externally reachable base URL, e.g. https://dav.example.org
//	CARDDAV_LISTEN           Listen address, default :8080
//	CARDDAV_BASIC_USER       HTTP Basic auth username (optional)
//	CARDDAV_BASIC_PASS       HTTP Basic auth password (optional)
//
// TLS is handled by a reverse proxy (nginx, Caddy, Traefik). Never expose plain HTTP.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/secbyd/proton-carddav/internal/auth"
	"github.com/secbyd/proton-carddav/internal/dav"
	protonbridge "github.com/secbyd/proton-carddav/internal/proton"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "auth" {
		if err := auth.Bootstrap(); err != nil {
			log.Fatalf("auth: %v", err)
		}
		return
	}

	runServe()
}

// runServe is the main CardDAV server path.
func runServe() {
	cfg := loadConfig()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("proton-carddav: authenticating as %s", cfg.protonUser)

	// otpFn is called only when Proton signals TOTP is required.
	// In daemon/non-interactive use, set PROTON_TOTP in the environment.
	otpFn := func() string {
		if v := os.Getenv("PROTON_TOTP"); v != "" {
			return v
		}
		fmt.Print("TOTP code: ")
		var code string
		fmt.Scanln(&code) //nolint:errcheck
		return code
	}

	// NewClientAndBridge performs the full verified Proton auth sequence:
	// SRP login → TOTP (if HasTOTP bitmask set) → GetSalts → SaltForKey
	// → protonapi.Unlock → returns ready Bridge with unlocked keyring.
	bridge, err := protonbridge.NewClientAndBridge(
		ctx,
		cfg.protonUser,
		cfg.protonPass,
		cfg.protonMboxPass,
		otpFn,
	)
	if err != nil {
		log.Fatalf("proton-carddav: login failed: %v", err)
	}
	defer bridge.Close(context.Background())

	davServer := dav.NewServer(cfg.baseURL, bridge)

	var handler http.Handler = davServer
	if cfg.basicUser != "" {
		handler = basicAuth(cfg.basicUser, cfg.basicPass, davServer)
	}

	srv := &http.Server{
		Addr:         cfg.listen,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("proton-carddav: listening on %s", cfg.listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("proton-carddav: serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("proton-carddav: shutting down")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
}

// ── config ────────────────────────────────────────────────────────────────────

type config struct {
	protonUser     string
	protonPass     string
	protonMboxPass string
	baseURL        string
	listen         string
	basicUser      string
	basicPass      string
}

// loadConfig prefers auth.json (when BRIDGE_PASSWORD is set) over individual
// environment variables.
func loadConfig() config {
	if os.Getenv("BRIDGE_PASSWORD") != "" {
		cfg, err := auth.Load()
		if err != nil {
			log.Fatalf("proton-carddav: load auth.json: %v", err)
		}
		return config{
			protonUser:     cfg.ProtonUsername,
			protonPass:     cfg.ProtonPassword,
			protonMboxPass: cfg.ProtonMboxPass,
			baseURL:        envOr("CARDDAV_BASE_URL", "http://localhost:8080"),
			listen:         envOr("CARDDAV_LISTEN", ":8080"),
			basicUser:      os.Getenv("CARDDAV_BASIC_USER"),
			basicPass:      os.Getenv("CARDDAV_BASIC_PASS"),
		}
	}

	return config{
		protonUser:     mustEnv("PROTON_USERNAME"),
		protonPass:     mustEnv("PROTON_PASSWORD"),
		protonMboxPass: os.Getenv("PROTON_MBOX_PASSWORD"),
		baseURL:        envOr("CARDDAV_BASE_URL", "http://localhost:8080"),
		listen:         envOr("CARDDAV_LISTEN", ":8080"),
		basicUser:      os.Getenv("CARDDAV_BASIC_USER"),
		basicPass:      os.Getenv("CARDDAV_BASIC_PASS"),
	}
}

// basicAuth wraps a handler with HTTP Basic authentication.
func basicAuth(user, pass string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="proton-carddav"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
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
