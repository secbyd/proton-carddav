// Package sync implements the bidirectional sync engine between a Proton
// Bridge and a Synology CardDAV server.
//
// Conflict policy (set in auth.json or via ConflictPolicy field):
//
//	"duplicate"      (default) — preserve both versions with a suffix UID
//	"proton-wins"    — Proton version overwrites Synology on conflict
//	"synology-wins"  — Synology version overwrites Proton on conflict
package sync

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	protonapi "github.com/ProtonMail/go-proton-api"
	vcard "github.com/emersion/go-vcard"

	"github.com/secbyd/proton-carddav/internal/auth"
	"github.com/secbyd/proton-carddav/internal/cache"
	"github.com/secbyd/proton-carddav/internal/proton"
	"github.com/secbyd/proton-carddav/internal/synology"
)

// Engine holds the two side-clients and the local state cache.
type Engine struct {
	proton   *proton.Bridge
	synology *synology.Client
	cache    *cache.DB
	policy   string
}

// NewEngine authenticates with ProtonMail, opens the local sync cache, and
// returns a ready Engine. It is the constructor used by cmd/proton-sync.
//
// Session lifecycle:
//  1. If cfg.ProtonAuth contains a valid UID + RefreshToken, a silent token
//     refresh is attempted — no password or TOTP required.
//  2. On refresh failure (expired/revoked) a full SRP login is performed.
//     TOTP is prompted interactively in that case.
//  3. The resulting (possibly new) Auth tokens are written back to auth.json
//     so the next run can resume silently.
func NewEngine(ctx context.Context, cfg *auth.Config) (*Engine, error) {
	// Convert stored ProtonAuthTokens -> *protonapi.Auth for the bridge.
	var existingAuth *protonapi.Auth
	if cfg.ProtonAuth != nil && cfg.ProtonAuth.UID != "" {
		existingAuth = &protonapi.Auth{
			UID:          cfg.ProtonAuth.UID,
			AccessToken:  cfg.ProtonAuth.AccessToken,
			RefreshToken: cfg.ProtonAuth.RefreshToken,
		}
	}

	// otpFn is only called on a full SRP login (refresh failed or first run).
	otpFn := func() string {
		fmt.Print("TOTP code: ")
		var code string
		fmt.Scanln(&code) //nolint:errcheck
		return code
	}

	bridge, newAuth, err := proton.NewClientAndBridge(
		ctx,
		existingAuth,
		cfg.ProtonUsername,
		cfg.ProtonPassword,
		cfg.ProtonMboxPass,
		otpFn,
	)
	if err != nil {
		return nil, fmt.Errorf("proton auth: %w", err)
	}

	// Persist the (possibly refreshed) tokens so the next run is silent.
	cfg.ProtonAuth = &auth.ProtonAuthTokens{
		UID:          newAuth.UID,
		AccessToken:  newAuth.AccessToken,
		RefreshToken: newAuth.RefreshToken,
	}
	if saveErr := auth.Save(cfg); saveErr != nil {
		// Non-fatal: log and continue. The session is live; the next run will
		// just fall back to a full login again.
		log.Printf("warning: could not persist updated auth tokens: %v", saveErr)
	}

	policy := cfg.ConflictPolicy
	if policy == "" {
		policy = "duplicate"
	}

	engine, err := newEngineFromBridge(
		bridge,
		cfg.SynologyURL,
		cfg.SynologyAddressbookPath,
		cfg.SynologyUsername,
		cfg.SynologyPassword,
		policy,
	)
	if err != nil {
		bridge.Close(ctx)
		return nil, err
	}
	return engine, nil
}

// newEngineFromBridge constructs an Engine from an already-authenticated Bridge.
// Used internally and in tests.
func newEngineFromBridge(
	bridge *proton.Bridge,
	synologyURL, synologyBook, synologyUser, synologyPass string,
	conflictPolicy string,
) (*Engine, error) {
	sc := synology.NewClient(synologyURL, synologyBook, synologyUser, synologyPass)

	db, err := cache.Open("sync-cache.db")
	if err != nil {
		return nil, fmt.Errorf("cache open: %w", err)
	}

	return &Engine{
		proton:   bridge,
		synology: sc,
		cache:    db,
		policy:   conflictPolicy,
	}, nil
}

// Close releases the cache DB handle and logs out the Proton session.
func (e *Engine) Close() {
	e.cache.Close()
	e.proton.Close(context.Background())
}

// SyncOnce performs one full bidirectional sync cycle.
func (e *Engine) SyncOnce(ctx context.Context) error {
	log.Println("sync: fetching contacts from Proton ...")
	pCards, err := e.proton.ListCards(ctx)
	if err != nil {
		return fmt.Errorf("list proton: %w", err)
	}

	log.Println("sync: fetching contacts from Synology ...")
	sContacts, err := e.synology.ListContacts(ctx)
	if err != nil {
		return fmt.Errorf("list synology: %w", err)
	}

	// Index both sides by UID.
	pMap := make(map[string]proton.CardObject, len(pCards))
	for _, c := range pCards {
		pMap[c.UID] = c
	}
	sMap := make(map[string]synology.Contact, len(sContacts))
	for _, c := range sContacts {
		sMap[c.UID] = c
	}

	// Union of all UIDs seen on either side.
	allUIDs := make(map[string]struct{}, len(pMap)+len(sMap))
	for uid := range pMap {
		allUIDs[uid] = struct{}{}
	}
	for uid := range sMap {
		allUIDs[uid] = struct{}{}
	}

	var errUIDs []string
	for uid := range allUIDs {
		if err := e.syncUID(ctx, uid, pMap, sMap); err != nil {
			log.Printf("sync: uid %s: %v", uid, err)
			errUIDs = append(errUIDs, uid)
		}
	}

	if len(errUIDs) > 0 {
		return fmt.Errorf("sync completed with %d errors (UIDs: %s)",
			len(errUIDs), strings.Join(errUIDs, ", "))
	}

	log.Printf("sync: done. %d Proton, %d Synology contacts.",
		len(pCards), len(sContacts))
	return nil
}

// syncUID resolves a single UID across both sides using the cached ETags.
func (e *Engine) syncUID(
	ctx context.Context,
	uid string,
	pMap map[string]proton.CardObject,
	sMap map[string]synology.Contact,
) error {
	cached, err := e.cache.Get(uid)
	if err != nil {
		return fmt.Errorf("cache get: %w", err)
	}

	pc, inProton := pMap[uid]
	sc, inSynology := sMap[uid]

	pChanged := inProton && pc.ETag != cached.ProtonETag
	sChanged := inSynology && sc.ETag != cached.SynologyETag
	firstSeen := cached.SyncedAt.IsZero()

	switch {
	case pChanged && sChanged && !firstSeen:
		return e.handleConflict(ctx, uid, pc, sc)

	case (pChanged && !sChanged) || (inProton && !inSynology):
		log.Printf("sync: uid %s: Proton -> Synology", uid)
		etag, err := e.synology.PutContact(ctx, uid, pc.VCard)
		if err != nil {
			return fmt.Errorf("put synology: %w", err)
		}
		return e.cache.Upsert(cache.ContactState{
			UID: uid, ProtonETag: pc.ETag, SynologyETag: etag, SyncedAt: time.Now(),
		})

	case (sChanged && !pChanged) || (inSynology && !inProton):
		log.Printf("sync: uid %s: Synology -> Proton", uid)
		obj, _, err := e.proton.UpsertCardByVCard(ctx, uid+".vcf", sc.VCard)
		if err != nil {
			return fmt.Errorf("upsert proton: %w", err)
		}
		return e.cache.Upsert(cache.ContactState{
			UID: uid, ProtonETag: obj.ETag, SynologyETag: sc.ETag, SyncedAt: time.Now(),
		})

	case !inProton && inSynology && !firstSeen:
		log.Printf("sync: uid %s: deleted on Proton -> delete on Synology", uid)
		if err := e.synology.DeleteContact(ctx, uid); err != nil {
			return err
		}
		return e.cache.Delete(uid)

	case inProton && !inSynology && !firstSeen:
		log.Printf("sync: uid %s: deleted on Synology -> delete on Proton", uid)
		if err := e.proton.DeleteCardByHref(ctx, pc.Href); err != nil {
			return err
		}
		return e.cache.Delete(uid)

	default:
		return nil
	}
}

// handleConflict implements the configured conflict resolution policy.
func (e *Engine) handleConflict(
	ctx context.Context,
	uid string,
	pc proton.CardObject,
	sc synology.Contact,
) error {
	switch e.policy {
	case "proton-wins":
		log.Printf("sync: uid %s: conflict -> Proton wins", uid)
		etag, err := e.synology.PutContact(ctx, uid, pc.VCard)
		if err != nil {
			return err
		}
		return e.cache.Upsert(cache.ContactState{
			UID: uid, ProtonETag: pc.ETag, SynologyETag: etag, SyncedAt: time.Now(),
		})

	case "synology-wins":
		log.Printf("sync: uid %s: conflict -> Synology wins", uid)
		obj, _, err := e.proton.UpsertCardByVCard(ctx, pc.Href, sc.VCard)
		if err != nil {
			return err
		}
		return e.cache.Upsert(cache.ContactState{
			UID: uid, ProtonETag: obj.ETag, SynologyETag: sc.ETag, SyncedAt: time.Now(),
		})

	default: // "duplicate"
		log.Printf("sync: uid %s: conflict -> duplicate", uid)
		pDupUID := uid + "-conflict-proton"
		pDupVCard := appendConflictSuffix(pc.VCard, pDupUID, "-conflict-proton")
		sETag1, err := e.synology.PutContact(ctx, pDupUID, pDupVCard)
		if err != nil {
			return fmt.Errorf("dup proton->synology: %w", err)
		}
		sDupUID := uid + "-conflict-synology"
		sDupVCard := appendConflictSuffix(sc.VCard, sDupUID, "-conflict-synology")
		pDupObj, _, err := e.proton.UpsertCardByVCard(ctx, sDupUID+".vcf", sDupVCard)
		if err != nil {
			return fmt.Errorf("dup synology->proton: %w", err)
		}
		if err := e.cache.Upsert(cache.ContactState{
			UID: pDupUID, ProtonETag: "", SynologyETag: sETag1, SyncedAt: time.Now(),
		}); err != nil {
			return err
		}
		if err := e.cache.Upsert(cache.ContactState{
			UID: sDupUID, ProtonETag: pDupObj.ETag, SynologyETag: "", SyncedAt: time.Now(),
		}); err != nil {
			return err
		}
		return e.cache.Delete(uid)
	}
}

// appendConflictSuffix rewrites the UID and FN fields of a vCard to mark it
// as a conflict copy.
func appendConflictSuffix(vcBytes []byte, newUID, fnSuffix string) []byte {
	card, err := vcard.NewDecoder(bytes.NewReader(vcBytes)).Decode()
	if err != nil {
		return vcBytes
	}
	card.SetValue(vcard.FieldUID, newUID)
	if fn := card.Get(vcard.FieldFormattedName); fn != nil {
		fn.Value += fnSuffix
	}
	var buf bytes.Buffer
	if err := vcard.NewEncoder(&buf).Encode(card); err != nil {
		return vcBytes
	}
	return buf.Bytes()
}
