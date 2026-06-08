// Package proton wraps go-proton-api for contact operations.
package proton

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	protonapi "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	vcard "github.com/emersion/go-vcard"
)

type Contact struct {
	UID        string
	ProtonID   string
	ETag       string
	VCard      []byte
	ModifyTime time.Time
}

type Client struct {
	api     *protonapi.Client
	keyring *crypto.KeyRing
}

// NewClient authenticates with Proton via SRP. otpFn is called for TOTP
// challenge during bootstrap (pass nil in daemon mode).
func NewClient(ctx context.Context, username, password, mboxPass string, otpFn func() string) (*Client, error) {
	m := protonapi.New(
		protonapi.WithHostURL("https://mail.proton.me"),
		protonapi.WithAppVersion("Other/1.0"),
	)

	c, auth, err := m.NewClientWithLogin(ctx, username, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("proton login: %w", err)
	}

	if auth.TwoFactor.Enabled == 1 && otpFn != nil {
		if err := c.Auth2FA(ctx, protonapi.TwoFactorInput{
			TwoFactorCode: otpFn(),
		}); err != nil {
			return nil, fmt.Errorf("proton 2FA: %w", err)
		}
	}

	user, err := c.GetUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("proton get user: %w", err)
	}

	if mboxPass == "" {
		mboxPass = password
	}
	kr, err := user.Keys.Unlock(auth.KeySalt, []byte(mboxPass))
	if err != nil {
		return nil, fmt.Errorf("proton unlock keyring: %w", err)
	}

	return &Client{api: c, keyring: kr}, nil
}

func (c *Client) Close(ctx context.Context) { _ = c.api.AuthDelete(ctx) }

func (c *Client) ListContacts(ctx context.Context) ([]Contact, error) {
	all, err := c.api.GetAllContacts(ctx)
	if err != nil {
		return nil, fmt.Errorf("proton list contacts: %w", err)
	}
	out := make([]Contact, 0, len(all))
	for _, pc := range all {
		contact, err := c.toContact(pc)
		if err != nil {
			continue
		}
		out = append(out, contact)
	}
	return out, nil
}

func (c *Client) GetContact(ctx context.Context, protonID string) (Contact, error) {
	pc, err := c.api.GetContact(ctx, protonID)
	if err != nil {
		return Contact{}, fmt.Errorf("proton get contact %s: %w", protonID, err)
	}
	return c.toContact(pc)
}

func (c *Client) CreateContact(ctx context.Context, vcBytes []byte) (Contact, error) {
	cards, err := c.buildCards(vcBytes)
	if err != nil {
		return Contact{}, err
	}
	resps, err := c.api.CreateContacts(ctx, protonapi.CreateContactsReq{
		Contacts:  []protonapi.ContactCards{{Cards: cards}},
		Overwrite: 0,
		Labels:    0,
	})
	if err != nil {
		return Contact{}, fmt.Errorf("proton create contact: %w", err)
	}
	if len(resps) == 0 || resps[0].Response.Code != 1000 {
		return Contact{}, fmt.Errorf("proton create contact: unexpected response code")
	}
	return c.toContact(resps[0].Response.Contact)
}

func (c *Client) UpdateContact(ctx context.Context, protonID string, vcBytes []byte) (Contact, error) {
	cards, err := c.buildCards(vcBytes)
	if err != nil {
		return Contact{}, err
	}
	updated, err := c.api.UpdateContact(ctx, protonID, protonapi.UpdateContactReq{Cards: cards})
	if err != nil {
		return Contact{}, fmt.Errorf("proton update contact %s: %w", protonID, err)
	}
	return c.toContact(updated)
}

func (c *Client) DeleteContact(ctx context.Context, protonID string) error {
	return c.api.DeleteContacts(ctx, protonapi.DeleteContactsReq{IDs: []string{protonID}})
}

func (c *Client) toContact(pc protonapi.Contact) (Contact, error) {
	merged, err := pc.Cards.Merge(c.keyring)
	if err != nil {
		return Contact{}, fmt.Errorf("merge cards %s: %w", pc.ID, err)
	}

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
	if merged.Get(vcard.FieldUID) == nil {
		merged.SetValue(vcard.FieldUID, uid)
	}

	vcBytes, err := encodeVCard(merged)
	if err != nil {
		return Contact{}, fmt.Errorf("encode vcard %s: %w", pc.ID, err)
	}

	return Contact{
		UID:        uid,
		ProtonID:   pc.ID,
		ETag:       etagOf(vcBytes),
		VCard:      vcBytes,
		ModifyTime: time.Unix(pc.ModifyTime, 0),
	}, nil
}

func (c *Client) buildCards(vcBytes []byte) (protonapi.Cards, error) {
	sig, err := c.keyring.SignDetached(crypto.NewPlainMessageFromString(string(vcBytes)))
	if err != nil {
		return nil, fmt.Errorf("sign card: %w", err)
	}
	armoredSig, err := sig.GetArmored()
	if err != nil {
		return nil, fmt.Errorf("armor sig: %w", err)
	}
	return protonapi.Cards{
		&protonapi.Card{
			Type:      protonapi.CardTypeSigned,
			Data:      string(vcBytes),
			Signature: armoredSig,
		},
	}, nil
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
