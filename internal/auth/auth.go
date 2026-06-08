// Package auth handles encrypted credential storage and interactive bootstrap.
//
// auth.json layout (on disk):
//
//	{
//	  "bridge_password_hint": "...",
//	  "salt":   "<base64 scrypt salt>",
//	  "nonce":  "<base64>",
//	  "cipher": "<base64>"   // AES-256-GCM ciphertext of inner JSON
//	}
//
// The AES key is derived with scrypt from the bridge password that is printed
// once during `auth` and must be supplied via BRIDGE_PASSWORD env var
// (or prompted) on every subsequent run.
//
// Inner JSON (plaintext after decryption):
//
//	{
//	  "proton_username":    "...",
//	  "proton_password":    "...",
//	  "proton_mbox_pass":   "...",
//	  "synology_url":       "https://nas.example.org:5006",
//	  "synology_username":  "...",
//	  "synology_password":  "...",
//	  "synology_addressbook_path": "/carddav/...",
//	  "sync_interval_sec":  300,
//	  "conflict_policy":    "duplicate"
//	}
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"golang.org/x/crypto/scrypt"
)

const authFile = "auth.json"

// Config is the decrypted runtime configuration.
type Config struct {
	ProtonUsername          string `json:"proton_username"`
	ProtonPassword          string `json:"proton_password"`
	ProtonMboxPass          string `json:"proton_mbox_pass"`
	SynologyURL             string `json:"synology_url"`
	SynologyUsername        string `json:"synology_username"`
	SynologyPassword        string `json:"synology_password"`
	SynologyAddressbookPath string `json:"synology_addressbook_path"`
	SyncIntervalSec         int    `json:"sync_interval_sec"`
	ConflictPolicy          string `json:"conflict_policy"`
}

type envelope struct {
	BridgePasswordHint string `json:"bridge_password_hint"`
	Salt               string `json:"salt"`
	Nonce              string `json:"nonce"`
	Cipher             string `json:"cipher"`
}

// Bootstrap runs the interactive first-time setup and writes auth.json.
func Bootstrap() error {
	fmt.Println("=== proton-sync auth bootstrap ===")

	cfg := Config{
		SyncIntervalSec: 300,
		ConflictPolicy:  "duplicate",
	}

	cfg.ProtonUsername = prompt("ProtonMail username: ", false)
	cfg.ProtonPassword = prompt("ProtonMail account password: ", true)
	mbox := prompt("ProtonMail mailbox password (leave blank = same as above): ", true)
	if mbox != "" {
		cfg.ProtonMboxPass = mbox
	}

	fmt.Println("\n--- Synology CardDAV ---")
	cfg.SynologyURL = prompt("Synology CardDAV URL (e.g. https://nas.example.org:5006): ", false)
	cfg.SynologyUsername = prompt("Synology username: ", false)
	cfg.SynologyPassword = prompt("Synology password: ", true)
	cfg.SynologyAddressbookPath = prompt("Address book path (e.g. /carddav/principal/addressbooks/proton/): ", false)

	bp, err := generateBridgePassword(32)
	if err != nil {
		return fmt.Errorf("generate bridge password: %w", err)
	}

	fmt.Printf("\n\033[1;33m⚠  Bridge password (save this — it cannot be recovered):\n\n   %s\n\n\033[0m", bp)
	fmt.Println("Set BRIDGE_PASSWORD=<value> before running sync/daemon.")

	if err := writeEncrypted(cfg, bp); err != nil {
		return fmt.Errorf("write auth.json: %w", err)
	}
	return nil
}

// Load decrypts auth.json using the bridge password.
func Load() (*Config, error) {
	bp := os.Getenv("BRIDGE_PASSWORD")
	if bp == "" {
		bp = prompt("Bridge password: ", true)
	}
	return readEncrypted(bp)
}

func writeEncrypted(cfg Config, bridgePass string) error {
	plain, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	key, err := deriveKey(bridgePass, salt)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nil, nonce, plain, nil)

	env := envelope{
		BridgePasswordHint: "set BRIDGE_PASSWORD env var or enter at prompt",
		Salt:               base64.StdEncoding.EncodeToString(salt),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
		Cipher:             base64.StdEncoding.EncodeToString(ciphertext),
	}

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(authFile, data, 0600)
}

func readEncrypted(bridgePass string) (*Config, error) {
	data, err := os.ReadFile(authFile)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w (run 'proton-sync auth' first)", authFile, err)
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse %s: %w", authFile, err)
	}

	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, errors.New("bad salt in auth.json")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, errors.New("bad nonce in auth.json")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Cipher)
	if err != nil {
		return nil, errors.New("bad cipher in auth.json")
	}

	key, err := deriveKey(bridgePass, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: wrong bridge password?")
	}

	var cfg Config
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

func deriveKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
}

func generateBridgePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[n.Int64()]
	}
	return string(b), nil
}
