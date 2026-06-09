// Package proton implements the ProtonMail contact adapter.
//
// Key design decisions driven by the actual go-proton-api v0.4.0 types:
//
//  1. Two-factor auth: Auth.TwoFA.Enabled is a TwoFAStatus bitmask;
//     HasTOTP (1<<0) indicates TOTP is required. The 2FA call takes
//     Auth2FAReq{TwoFactorCode: code}.
//
//  2. Key unlock: there is no Keys.Unlock(salt, pass) helper. Instead:
//       a. Call client.GetSalts() to obtain []Salt{ID, KeySalt}.
//       b. Call salts.SaltForKey(mailboxPassword, primaryKeyID) to derive
//          the salted key password using Proton's MailboxPassword KDF.
//       c. Call proton.Unlock(user, addresses, saltedKeyPass) which returns
//          (*crypto.KeyRing, map[string]*crypto.KeyRing, error).
//
//  3. Cards.Merge(*crypto.KeyRing) decrypts + verifies all card types and
//     returns a merged vcard.Card ready for re-serialisation.
//
//  4. Session persistence (hydroxide pattern):
//     Pass an existing *protonapi.Auth to NewClientAndBridge to attempt a
//     silent token refresh (NewClientWithRefresh). TOTP is only required
//     on the very first login or after a session is revoked server-side.
package proton

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	protonapi "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	vcard "github.com/emersion/go-vcard"
)

// ── Public types ──────────────────────────────────────────────────────────────

// CardObject is the canonical per-contact representation used by the sync engine.
type CardObject struct {
	// UID is the stable vCard UID used as the filename base.
	UID string
	// Href is the per-resource filename, e.g. "<uid>.vcf".
	Href string
	// ETag is a double-quoted SHA-256 over the canonical vCard bytes.
	ETag string
	// VCard holds RFC 6350 vCard 4.0 bytes.
	VCard []byte
	// ProtonID is the Proton-side contact ID used in CRUD calls.
	ProtonID string
	// ModifyTime is the server-side last-modification timestamp.
	ModifyTime time.Time
}

// ErrNotFound is returned when a card cannot be located by href.
var ErrNotFound = errors.New("proton: card not found")

// ── Bridge ────────────────────────────────────────────────────────────────────

// Bridge holds an authenticated Proton API client and the user's primary keyring.
type Bridge struct {
	client  *protonapi.Client
	keyring *crypto.KeyRing
}

// NewManager returns a configured go-proton-api Manager.
// Using the library default app version "go-proton-api" which is accepted
// by Proton's AuthInfo endpoint. "Other/1.0" was previously used here but
// caused AuthInfo to return an error response, leaving Modulus nil and
// triggering a nil pointer dereference in srp.NewAuth.
func NewManager() *protonapi.Manager {
	return protonapi.New(
		protonapi.WithAppVersion("go-proton-api"),
	)
}

// NewClientAndBridge establishes an authenticated Proton session and returns
// a ready Bridge plus the Auth tokens to be persisted for the next run.
//
// Session lifecycle (hydroxide pattern):
//  1. If existingAuth is non-nil and has a UID, attempt a silent token refresh
//     via NewClientWithRefresh — no password or TOTP needed.
//  2. If refresh fails (expired, revoked) or existingAuth is nil, fall back
//     to a full SRP login + optional TOTP.
//
// Parameters:
//   - existingAuth  Previously persisted Auth tokens; nil on first run.
//   - username      Proton account username (used for full login fallback).
//   - password      Proton login password (used for full login fallback).
//   - mboxPass      Mailbox password; empty string means single-password mode.
//   - otpFn         Called only when Proton requires TOTP during a full login.
//     May be nil if existingAuth is always valid (daemon mode without
//     re-auth). Will error if TOTP is required and otpFn is nil.
func NewClientAndBridge(
	ctx context.Context,
	existingAuth *protonapi.Auth,
	username, password, mboxPass string,
	otpFn func() string,
) (*Bridge, *protonapi.Auth, error) {
	m := NewManager()

	var (
		c    *protonapi.Client
		auth protonapi.Auth
		err  error
	)

	// ── Attempt silent token refresh first ────────────────────────────────
	if existingAuth != nil && existingAuth.UID != "" {
		c, auth, err = m.NewClientWithRefresh(ctx, existingAuth.UID, existingAuth.RefreshToken)
		if err == nil {
			log.Println("proton: session resumed via token refresh")
			goto unlock
		}
		log.Printf("proton: token refresh failed (%v) — falling back to full login", err)
	}

	// ── Full SRP login ────────────────────────────────────────────────────
	{
		c, auth, err = m.NewClientWithLogin(ctx, username, []byte(password))
		if err != nil {
			return nil, nil, fmt.Errorf("proton: SRP login: %w", err)
		}

		// TOTP 2FA — auth.TwoFA.Enabled is a bitmask: HasTOTP = 1<<0.
		if auth.TwoFA.Enabled&protonapi.HasTOTP != 0 {
			if otpFn == nil {
				return nil, nil, errors.New(
					"proton: TOTP required but no OTP function provided — " +
						"run 'proton-sync auth' to bootstrap a fresh session")
			}
			if err := c.Auth2FA(ctx, protonapi.Auth2FAReq{
				TwoFactorCode: otpFn(),
			}); err != nil {
				return nil, nil, fmt.Errorf("proton: 2FA: %w", err)
			}
		}
	}

unlock:
	// ── Fetch user + addresses ────────────────────────────────────────────
	user, err := c.GetUser(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("proton: get user: %w", err)
	}
	if len(user.Keys) == 0 {
		return nil, nil, errors.New("proton: user has no keys")
	}

	addresses, err := c.GetAddresses(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("proton: get addresses: %w", err)
	}

	// ── Derive salted mailbox password ────────────────────────────────────
	// Single-password mode: mailbox password == login password.
	if mboxPass == "" {
		mboxPass = password
	}

	salts, err := c.GetSalts(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("proton: get salts: %w", err)
	}

	saltedPass, err := salts.SaltForKey([]byte(mboxPass), user.Keys[0].ID)
	if err != nil {
		return nil, nil, fmt.Errorf("proton: salt key pass: %w", err)
	}

	// ── Unlock keyring ────────────────────────────────────────────────────
	userKR, _, err := protonapi.Unlock(user, addresses, saltedPass)
	if err != nil {
		return nil, nil, fmt.Errorf("proton: unlock keyring: %w", err)
	}

	return &Bridge{client: c, keyring: userKR}, &auth, nil
}

// NewBridge constructs a Bridge from an already-authenticated client and keyring.
// Use this when restoring a session from stored credentials.
func NewBridge(client *protonapi.Client, keyring *crypto.KeyRing) *Bridge {
	return &Bridge{client: client, keyring: keyring}
}

// Close logs out the authenticated session.
func (b *Bridge) Close(ctx context.Context) {
	_ = b.client.AuthDelete(ctx)
}

// ── Read operations ───────────────────────────────────────────────────────────

// ListCards returns all ProtonMail contacts as CardObjects.
func (b *Bridge) ListCards(ctx context.Context) ([]CardObject, error) {
	contacts, err := b.client.GetAllContacts(ctx)
	if err != nil {
		return nil, fmt.Errorf("proton: list contacts: %w", err)
	}
	out := make([]CardObject, 0, len(contacts))
	for _, c := range contacts {
		obj, err := b.contactToCardObject(c)
		if err != nil {
			// Skip unreadable contacts rather than aborting the whole sync.
			continue
		}
		out = append(out, obj)
	}
	return out, nil
}

// GetCardByHref locates a card by its href filename (e.g. "abc123.vcf").
func (b *Bridge) GetCardByHref(ctx context.Context, href string) (CardObject, error) {
	cards, err := b.ListCards(ctx)
	if err != nil {
		return CardObject{}, err
	}
	for _, c := range cards {
		if c.Href == href {
			return c, nil
		}
	}
	return CardObject{}, ErrNotFound
}

// ── Write operations ──────────────────────────────────────────────────────────

// UpsertCardByVCard creates or replaces a contact from raw vCard bytes.
// Returns (obj, created, error); created is true when a new contact was made.
func (b *Bridge) UpsertCardByVCard(ctx context.Context, href string, raw []byte) (CardObject, bool, error) {
	vc, err := parseVCard(raw)
	if err != nil {
		return CardObject{}, false, fmt.Errorf("proton: parse vcard: %w", err)
	}

	existing, lookupErr := b.GetCardByHref(ctx, href)

	if lookupErr == nil {
		// Contact already exists on Proton — update it.
		cards, err := b.buildProtonCards(vc)
		if err != nil {
			return CardObject{}, false, fmt.Errorf("proton: build cards for update: %w", err)
		}
		updated, err := b.client.UpdateContact(ctx, existing.ProtonID, protonapi.UpdateContactReq{Cards: cards})
		if err != nil {
			return CardObject{}, false, fmt.Errorf("proton: update contact: %w", err)
		}
		obj, err := b.contactToCardObject(updated)
		if err != nil {
			return CardObject{}, false, err
		}
		return obj, false, nil
	}

	// Contact does not exist — create it.
	cards, err := b.buildProtonCards(vc)
	if err != nil {
		return CardObject{}, false, fmt.Errorf("proton: build cards for create: %w", err)
	}
	resps, err := b.client.CreateContacts(ctx, protonapi.CreateContactsReq{
		Contacts:  []protonapi.ContactCards{{Cards: cards}},
		Overwrite: 0,
		Labels:    0,
	})
	if err != nil {
		return CardObject{}, false, fmt.Errorf("proton: create contact: %w", err)
	}
	if len(resps) == 0 || resps[0].Response.Code != 1000 {
		return CardObject{}, false, errors.New("proton: create contact: no success response")
	}
	obj, err := b.contactToCardObject(resps[0].Response.Contact)
	if err != nil {
		return CardObject{}, false, err
	}
	return obj, true, nil
}

// DeleteCardByHref removes the contact identified by href.
func (b *Bridge) DeleteCardByHref(ctx context.Context, href string) error {
	card, err := b.GetCardByHref(ctx, href)
	if err != nil {
		return err
	}
	return b.client.DeleteContacts(ctx, protonapi.DeleteContactsReq{IDs: []string{card.ProtonID}})
}

// ── Private helpers ───────────────────────────────────────────────────────────

// contactToCardObject converts a protonapi.Contact into a CardObject by
// decrypting/verifying all card types and serialising to vCard 4.0 bytes.
func (b *Bridge) contactToCardObject(pc protonapi.Contact) (CardObject, error) {
	// Cards.Merge decrypts encrypted cards and verifies signed cards using
	// the provided keyring, then merges all card types into one vcard.Card.
	merged, err := pc.Cards.Merge(b.keyring)
	if err != nil {
		return CardObject{}, fmt.Errorf("proton: merge cards for %s: %w", pc.ID, err)
	}

	// Resolve UID: prefer the vCard UID field, then the Proton metadata UID,
	// then fall back to the Proton contact ID.
	uid := ""
	if f := merged.Get(vcard.FieldUID); f != nil {
		uid = f.Value
	}
	if uid == "" {
		uid = pc.UID
	}
	if uid == "" {
		uid = pc.ID
	}
	uid = sanitiseUID(uid)

	// Ensure the merged card carries a UID field before serialisation.
	if merged.Get(vcard.FieldUID) == nil {
		merged.SetValue(vcard.FieldUID, uid)
	}

	vcBytes, err := encodeVCard(merged)
	if err != nil {
		return CardObject{}, fmt.Errorf("proton: encode vcard for %s: %w", pc.ID, err)
	}

	return CardObject{
		UID:        uid,
		Href:       uid + ".vcf",
		ETag:       etagOf(vcBytes),
		VCard:      vcBytes,
		ProtonID:   pc.ID,
		ModifyTime: time.Unix(pc.ModifyTime, 0),
	}, nil
}

// buildProtonCards encodes a vcard.Card into Proton's signed card format.
// The card is stored as CardTypeSigned so that Proton can verify its integrity.
func (b *Bridge) buildProtonCards(vc vcard.Card) (protonapi.Cards, error) {
	vcBytes, err := encodeVCard(vc)
	if err != nil {
		return nil, fmt.Errorf("encode vcard for signing: %w", err)
	}
	sig, err := b.keyring.SignDetached(crypto.NewPlainMessageFromString(string(vcBytes)))
	if err != nil {
		return nil, fmt.Errorf("sign card: %w", err)
	}
	armoredSig, err := sig.GetArmored()
	if err != nil {
		return nil, fmt.Errorf("armor signature: %w", err)
	}
	return protonapi.Cards{
		&protonapi.Card{
			Type:      protonapi.CardTypeSigned,
			Data:      string(vcBytes),
			Signature: armoredSig,
		},
	}, nil
}

// parseVCard decodes raw vCard bytes into a vcard.Card.
func parseVCard(raw []byte) (vcard.Card, error) {
	card, err := vcard.NewDecoder(bytes.NewReader(raw)).Decode()
	if err != nil {
		return nil, fmt.Errorf("parse vcard: %w", err)
	}
	return card, nil
}

// encodeVCard serialises a vcard.Card to RFC 6350 bytes.
func encodeVCard(vc vcard.Card) ([]byte, error) {
	var buf bytes.Buffer
	if err := vcard.NewEncoder(&buf).Encode(vc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// etagOf returns a double-quoted SHA-256 hex string over b.
func etagOf(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// sanitiseUID replaces characters that are invalid in URL path segments.
func sanitiseUID(uid string) string {
	return strings.NewReplacer("/", "-", " ", "-", ":", "-").Replace(uid)
}
