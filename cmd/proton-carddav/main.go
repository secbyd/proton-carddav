// proton-carddav is a single-user RFC 6352 CardDAV bridge for ProtonMail.
//
// Usage:
//
//	export PROTON_USERNAME=you@proton.me
//	export PROTON_PASSWORD=yourpassword
//	export PROTON_MBOX_PASSWORD=yourmailboxpassword   # two-password mode only
//	export CARDDAV_BASE_URL=https://carddav.example.org
//	export CARDDAV_LISTEN=:8080
//	export CARDDAV_BASIC_USER=dav
//	export CARDDAV_BASIC_PASS=secret
//	proton-carddav
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

	protonapi "github.com/ProtonMail/go-proton-api"

	"github.com/secbyd/proton-carddav/internal/dav"
	protonbridge "github.com/secbyd/proton-carddav/internal/proton"
)

func main() {
	cfg := loadConfig()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("proton-carddav: authenticating as %s", cfg.protonUser)
	client, kr, err := loginProton(ctx, cfg)
	if err != nil {
		log.Fatalf("proton-carddav: login failed: %v", err)
	}
	defer client.AuthDelete(context.Background()) //nolint:errcheck

	bridge := protonbridge.NewBridge(client, kr)
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

// loginProton authenticates with Proton and unlocks the user keyring.
// Handles both one-password and two-password modes.
func loginProton(ctx context.Context, cfg config) (*protonapi.Client, interface{ /* *crypto.KeyRing */ }, error) {
	m := protonapi.New(
		protonapi.WithHostURL("https://mail.proton.me"),
		protonapi.WithAppVersion("Other/1.0"),
	)

	c, auth, err := m.NewClientWithLogin(ctx, cfg.protonUser, []byte(cfg.protonPass))
	if err != nil {
		return nil, nil, fmt.Errorf("login: %w", err)
	}

	user, err := c.GetUser(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("get user: %w", err)
	}

	// In one-password mode the mailbox password equals the account password.
	mboxPass := cfg.protonMboxPass
	if mboxPass == "" {
		mboxPass = cfg.protonPass
	}

	kr, err := user.Keys.Unlock(auth.KeySalt, []byte(mboxPass))
	if err != nil {
		return nil, nil, fmt.Errorf("unlock keyring: %w", err)
	}

	return c, kr, nil
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

func loadConfig() config {
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

// basicAuth wraps a handler with HTTP Basic Authentication.
func basicAuth(user, pass string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="ProtonMail CardDAV"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
