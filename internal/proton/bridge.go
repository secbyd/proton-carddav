// Package proton implements the ProtonMail contact adapter for the CardDAV bridge.
//
// ProtonMail stores contacts as signed/encrypted Card objects. This adapter:
//  1. Calls go-proton-api to retrieve contacts.
//  2. Decrypts and verifies each card with the user keyring via Cards.Merge.
//  3. Serialises the merged vcard.Card to RFC 6350 vCard 4.0 bytes.
//  4. On writes, encodes a ParsedVCard back into a signed Proton Card and
//     calls CreateContacts / UpdateContact accordingly.
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

// CardObject is the canonical per-contact representation used by the DAV layer.
type CardObject struct {
	// UID is the stable vCard UID, also used as the filename base.
	UID string
	// Href is the per-resource filename, e.g. "<uid>.vcf".
	Href string
	// ETag is a double-quoted SHA-256 over the canonical vCard bytes.
	ETag string
	// VCard holds RFC 6350 vCard 4.0 bytes ready to serve over HTTP.
	VCard []byte
	// ProtonID is the Proton contact ID used in CRUD calls.
	ProtonID string
	// ModifyTime is the server-side last-modification time.
	ModifyTime time.Time
}

// ErrNotFound is returned when no matching card can be located.
var ErrNotFound = errors.New("proton: card not found")

// Bridge wraps an authenticated Proton API client and the user's keyring.
type Bridge struct {
	client  *protonapi.Client
	keyring *crypto.KeyRing
}

// NewBridge constructs a Bridge from an already-authenticated client and
// the user's unlocked primary keyring.
func NewBridge(client *protonapi.Client, keyring *crypto.KeyRing) *Bridge {
	return &Bridge{client: client, keyring: keyring}
}

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
			// Skip broken/unreadable contacts; a real deployment should log here.
			continue
		}
		out = append(out, obj)
	}
	return out, nil
}

// GetCardByHref locates a card by its filename (e.g. "abc123.vcf").
// It fetches the full list and does a linear scan.
// A production implementation should maintain an in-memory index.
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

// UpsertCardByVCard creates or replaces a contact from raw vCard bytes.
// Returns (obj, created, error); created is true when a new contact was made.
func (b *Bridge) UpsertCardByVCard(ctx context.Context, href string, raw []byte) (CardObject, bool, error) {
	vc, err := parseVCard(raw)
	if err != nil {
		return CardObject{}, false, fmt.Errorf("proton: parse vcard: %w", err)
	}

	existing, lookupErr := b.GetCardByHref(ctx, href)

	if lookupErr == nil {
		// ── UPDATE ──
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

	// ── CREATE ──
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

// DeleteCardByHref removes the contact whose Href matches.
func (b *Bridge) DeleteCardByHref(ctx context.Context, href string) error {
	card, err := b.GetCardByHref(ctx, href)
	if err != nil {
		return err
	}
	return b.client.DeleteContacts(ctx, protonapi.DeleteContactsReq{IDs: []string{card.ProtonID}})
}

// ── private helpers ───────────────────────────────────────────────────────────

// contactToCardObject converts a protonapi.Contact into a CardObject by
// decrypting/verifying all card blocks via Cards.Merge and serialising the
// resulting vcard.Card to RFC 6350 bytes.
func (b *Bridge) contactToCardObject(c protonapi.Contact) (CardObject, error) {
	// Cards.Merge decrypts encrypted card blocks and verifies signatures,
	// then merges them into a single vcard.Card — this is the canonical
	// way go-proton-api exposes decrypted contact content.
	merged, err := c.Cards.Merge(b.keyring)
	if err != nil {
		return CardObject{}, fmt.Errorf("proton: merge cards for %s: %w", c.ID, err)
	}

	// Determine a stable UID: prefer the vCard UID field, then Proton's UID
	// field, finally fall back to the opaque contact ID.
	uidStr := ""
	if f := merged.Get(vcard.FieldUID); f != nil {
		uidStr = f.Value
	}
	if uidStr == "" {
		uidStr = c.UID
	}
	if uidStr == "" {
		uidStr = c.ID
	}
	uidStr = sanitiseUID(uidStr)

	// Always embed the UID so clients can round-trip it.
	if merged.Get(vcard.FieldUID) == nil {
		merged.SetValue(vcard.FieldUID, uidStr)
	}

	vcBytes, err := encodeVCard(merged)
	if err != nil {
		return CardObject{}, fmt.Errorf("proton: encode vcard %s: %w", c.ID, err)
	}

	return CardObject{
		UID:        uidStr,
		Href:       uidStr + ".vcf",
		ETag:       etagOf(vcBytes),
		VCard:      vcBytes,
		ProtonID:   c.ID,
		ModifyTime: time.Unix(c.ModifyTime, 0),
	}, nil
}

// buildProtonCards converts a vcard.Card into the signed Proton card set
// required by CreateContacts / UpdateContact.
// We produce a single CardTypeSigned card containing the full vCard text.
// Sensitive per-contact data (PGP keys, etc.) would go in a separate
// CardTypeEncryptedAndSigned block if needed.
func (b *Bridge) buildProtonCards(vc vcard.Card) (protonapi.Cards, error) {
	vcBytes, err := encodeVCard(vc)
	if err != nil {
		return nil, err
	}

	// Sign the vCard text with the user's primary key.
	sig, err := b.keyring.SignDetached(crypto.NewPlainMessageFromString(string(vcBytes)))
	if err != nil {
		return nil, fmt.Errorf("proton: sign card data: %w", err)
	}
	armoredSig, err := sig.GetArmored()
	if err != nil {
		return nil, fmt.Errorf("proton: armor signature: %w", err)
	}

	return protonapi.Cards{
		&protonapi.Card{
			Type:      protonapi.CardTypeSigned,
			Data:      string(vcBytes),
			Signature: armoredSig,
		},
	}, nil
}

func parseVCard(raw []byte) (vcard.Card, error) {
	dec := vcard.NewDecoder(bytes.NewReader(raw))
	return dec.Decode()
}

func encodeVCard(vc vcard.Card) ([]byte, error) {
	var buf bytes.Buffer
	if err := vcard.NewEncoder(&buf).Encode(vc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func etagOf(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func sanitiseUID(uid string) string {
	return strings.NewReplacer("/", "-", " ", "-", ":", "-").Replace(uid)
}
