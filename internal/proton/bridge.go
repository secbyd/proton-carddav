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
package proton

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

// NewClientAndBridge performs full SRP login, optional TOTP 2FA, key-salt
// derivation, and keyring unlock. It returns a ready-to-use Bridge.
//
// Parameters:
//   - username     Proton account username
//   - password     Proton login password
//   - mboxPass     Mailbox password (pass empty string for single-password mode)
//   - otpFn        Called when Proton requires TOTP; may be nil in daemon mode
//     (will fail if 2FA is actually required when nil)
func NewClientAndBridge(
	ctx context.Context,
	username, password, mboxPass string,
	otpFn func() string,
) (*Bridge, error) {
	m := protonapi.New(
		protonapi.WithHostURL("https://mail.proton.me"),
		protonapi.WithAppVersion("Other/1.0"),
	)

	// ── Step 1: SRP login ──
	c, auth, err := m.NewClientWithLogin(ctx, username, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("proton: SRP login: %w", err)
	}

	// ── Step 2: TOTP 2FA (if required) ──
	// auth.TwoFA.Enabled is a bitmask: HasTOTP = 1<<0, HasFIDO2 = 1<<1.
	if auth.TwoFA.Enabled&protonapi.HasTOTP != 0 {
		if otpFn == nil {
			return nil, errors.New("proton: TOTP required but no OTP function provided")
		}
		if err := c.Auth2FA(ctx, protonapi.Auth2FAReq{
			TwoFactorCode: otpFn(),
		}); err != nil {
			return nil, fmt.Errorf("proton: 2FA: %w", err)
		}
	}

	// ── Step 3: Fetch user + addresses ──
	user, err := c.GetUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("proton: get user: %w", err)
	}
	if len(user.Keys) == 0 {
		return nil, errors.New("proton: user has no keys")
	}

	addresses, err := c.GetAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("proton: get addresses: %w", err)
	}

	// ── Step 4: Derive salted mailbox password ──
	// In single-password mode, the mailbox password equals the login password.
	if mboxPass == "" {
		mboxPass = password
	}

	salts, err := c.GetSalts(ctx)
	if err != nil {
		return nil, fmt.Errorf("proton: get salts: %w", err)
	}

	// SaltForKey uses the primary key ID to look up the correct salt entry
	// and applies Proton's bcrypt-derived MailboxPassword KDF.
	saltedPass, err := salts.SaltForKey([]byte(mboxPass), user.Keys[0].ID)
	if err != nil {
		return nil, fmt.Errorf("proton: salt key pass: %w", err)
	}

	// ── Step 5: Unlock keyring ──
	// proton.Unlock returns the user keyring and per-address keyrings.
	// We only need the user keyring for contact decryption.
	userKR, _, err := protonapi.Unlock(user, addresses, saltedPass)
	if err != nil {
		return nil, fmt.Errorf("proton: unlock keyring: %w", err)
	}

	return &Bridge{client: c, keyring: userKR}, nil
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
