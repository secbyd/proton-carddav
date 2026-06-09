// proton-carddav is a single-user RFC 6352 CardDAV bridge for ProtonMail.
//
// # Modes
//
//	proton-carddav auth    — interactive first-time setup; writes auth.json
//	proton-carddav serve   — start the CardDAV HTTP server (default when no arg)
//
// # Flags
//
//	-debug   Enable verbose debug logging (auth load, Proton API, DAV requests)
//
// # Environment variables
//
//	PROTON_USERNAME      ProtonMail account username
//	PROTON_PASSWORD      ProtonMail account password
//	PROTON_MBOX_PASSWORD Mailbox password (two-password mode only)
//	PROTON_TOTP          TOTP code for non-interactive 2FA
//	BRIDGE_PASSWORD      Bridge password to decrypt auth.json
//	CARDDAV_BASE_URL     Externally reachable base URL, e.g. https://dav.example.org
//	CARDDAV_LISTEN       Listen address, default :8080
//	CARDDAV_BASIC_USER   HTTP Basic auth username (optional)
//	CARDDAV_BASIC_PASS   HTTP Basic auth password (optional)
//
// TLS is handled by a reverse proxy (nginx, Caddy, Traefik).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	protonapi "github.com/ProtonMail/go-proton-api"
	"github.com/secbyd/proton-carddav/internal/auth"
	"github.com/secbyd/proton-carddav/internal/dav"
	protonbridge "github.com/secbyd/proton-carddav/internal/proton"
)

var debugMode bool

func debugf(format string, args ...any) {
	if debugMode {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func main() {
	flag.BoolVar(&debugMode, "debug", false, "Enable verbose debug logging")
	flag.Parse()

	if debugMode {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
		log.Println("[DEBUG] debug mode enabled")
	}

	args := flag.Args()
	if len(args) >= 1 && args[0] == "auth" {
		debugf("running bootstrap auth flow")
		if err := auth.Bootstrap(); err != nil {
			log.Fatalf("auth: %v", err)
		}
		return
	}

	runServe()
}

func runServe() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := loadConfig()
	debugf("config loaded: user=%s listen=%s baseURL=%s", cfg.protonUser, cfg.listen, cfg.baseURL)

	// otpFn is called only when Proton signals TOTP is required.
	otpFn := func() string {
		if v := os.Getenv("PROTON_TOTP"); v != "" {
			debugf("using PROTON_TOTP env var for 2FA")
			return v
		}
		fmt.Print("TOTP code: ")
		var code string
		fmt.Scanln(&code) //nolint:errcheck
		return code
	}

	// Attempt to restore a persisted session from auth.json (hydroxide pattern):
	// supply existing tokens so NewClientAndBridge can use NewClientWithRefresh
	// and skip a full SRP login + TOTP on every startup.
	var existingAuth *protonapi.Auth
	if os.Getenv("BRIDGE_PASSWORD") != "" {
		debugf("BRIDGE_PASSWORD set — loading cached session from auth.json")
		loadedCfg, err := auth.Load()
		if err != nil {
			log.Printf("proton-carddav: warning: could not load auth.json (%v) — will do full login", err)
		} else {
			if loadedCfg.ProtonAuth != nil {
				debugf("found persisted auth tokens UID=%s", loadedCfg.ProtonAuth.UID)
				existingAuth = &protonapi.Auth{
					UID:          loadedCfg.ProtonAuth.UID,
					AccessToken:  loadedCfg.ProtonAuth.AccessToken,
					RefreshToken: loadedCfg.ProtonAuth.RefreshToken,
				}
			}
			// Overlay credentials from auth.json when env vars are absent.
			if cfg.protonUser == "" {
				cfg.protonUser = loadedCfg.ProtonUsername
			}
			if cfg.protonPass == "" {
				cfg.protonPass = loadedCfg.ProtonPassword
			}
			if cfg.protonMboxPass == "" {
				cfg.protonMboxPass = loadedCfg.ProtonMboxPass
			}
		}
	}

	log.Printf("proton-carddav: authenticating as %s", cfg.protonUser)
	debugf("calling NewClientAndBridge existingAuth=%v", existingAuth != nil)

	bridge, newAuth, err := protonbridge.NewClientAndBridge(
		ctx,
		existingAuth,
		cfg.protonUser,
		cfg.protonPass,
		cfg.protonMboxPass,
		otpFn,
	)
	if err != nil {
		log.Fatalf("proton-carddav: login failed: %v", err)
	}
	defer bridge.Close(context.Background())
	debugf("Proton session established UID=%s", newAuth.UID)

	// Persist refreshed tokens so next startup can skip full SRP login.
	if os.Getenv("BRIDGE_PASSWORD") != "" {
		go persistTokens(newAuth)
	}

	davServer := dav.NewServer(cfg.baseURL, bridge)
	if debugMode {
		davServer.SetDebug(true)
	}

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
		log.Printf("proton-carddav: listening on %s (base URL %s)", cfg.listen, cfg.baseURL)
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

// persistTokens writes refreshed Proton auth tokens back to auth.json.
func persistTokens(a *protonapi.Auth) {
	debugf("persisting refreshed auth tokens UID=%s", a.UID)
	loadedCfg, err := auth.Load()
	if err != nil {
		log.Printf("proton-carddav: warning: could not reload auth.json for token persist: %v", err)
		return
	}
	loadedCfg.ProtonAuth = &auth.ProtonAuthTokens{
		UID:          a.UID,
		AccessToken:  a.AccessToken,
		RefreshToken: a.RefreshToken,
	}
	if err := auth.Save(loadedCfg); err != nil {
		log.Printf("proton-carddav: warning: could not save refreshed tokens: %v", err)
	}
}

type config struct {
	protonUser     string
	protonPass     string
	protonMboxPass string
	baseURL        string
	listen         string
	basicUser      string
	basicPass      string
}

// loadConfig reads credentials from environment variables.
// Values from auth.json (when BRIDGE_PASSWORD is set) are overlaid by the
// caller after auth.Load().
func loadConfig() config {
	return config{
		protonUser:     os.Getenv("PROTON_USERNAME"),
		protonPass:     os.Getenv("PROTON_PASSWORD"),
		protonMboxPass: os.Getenv("PROTON_MBOX_PASSWORD"),
		baseURL:        envOr("CARDDAV_BASE_URL", "http://localhost:8080"),
		listen:         envOr("CARDDAV_LISTEN", ":8080"),
		basicUser:      os.Getenv("CARDDAV_BASIC_USER"),
		basicPass:      os.Getenv("CARDDAV_BASIC_PASS"),
	}
}

func basicAuth(user, pass string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="proton-carddav"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		debugf("Basic Auth OK user=%q", u)
		next.ServeHTTP(w, r)
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
