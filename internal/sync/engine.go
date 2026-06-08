// Package sync implements the bidirectional sync engine.
//
// Conflict policy: "duplicate"
//   When both sides changed the same UID since the last sync, both versions
//   are preserved.  The Synology copy gets suffix "-conflict-proton" appended
//   to FN and a new UID; the Proton copy gets "-conflict-synology".  Both are
//   written back to both sides so neither loses data.
package sync

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	vcard "github.com/emersion/go-vcard"

	"github.com/secbyd/proton-carddav/internal/auth"
	"github.com/secbyd/proton-carddav/internal/cache"
	"github.com/secbyd/proton-carddav/internal/proton"
	"github.com/secbyd/proton-carddav/internal/synology"
)

type Engine struct {
	proton   *proton.Client
	synology *synology.Client
	cache    *cache.DB
	policy   string
}

func NewEngine(ctx context.Context, cfg *auth.Config) (*Engine, error) {
	pc, err := proton.NewClient(ctx,
		cfg.ProtonUsername, cfg.ProtonPassword, cfg.ProtonMboxPass,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("proton connect: %w", err)
	}

	sc := synology.NewClient(
		cfg.SynologyURL,
		cfg.SynologyAddressbookPath,
		cfg.SynologyUsername,
		cfg.SynologyPassword,
	)

	db, err := cache.Open("sync-cache.db")
	if err != nil {
		return nil, fmt.Errorf("cache: %w", err)
	}

	policy := cfg.ConflictPolicy
	if policy == "" {
		policy = "duplicate"
	}

	return &Engine{
		proton:   pc,
		synology: sc,
		cache:    db,
		policy:   policy,
	}, nil
}

func (e *Engine) Close() {
	e.cache.Close()
}

func (e *Engine) SyncOnce(ctx context.Context) error {
	log.Println("sync: fetching contacts from Proton ...")
	pContacts, err := e.proton.ListContacts(ctx)
	if err != nil {
		return fmt.Errorf("list proton: %w", err)
	}

	log.Println("sync: fetching contacts from Synology ...")
	sContacts, err := e.synology.ListContacts(ctx)
	if err != nil {
		return fmt.Errorf("list synology: %w", err)
	}

	pMap := make(map[string]proton.Contact, len(pContacts))
	for _, c := range pContacts {
		pMap[c.UID] = c
	}
	sMap := make(map[string]synology.Contact, len(sContacts))
	for _, c := range sContacts {
		sMap[c.UID] = c
	}

	allUIDs := make(map[string]struct{})
	for uid := range pMap {
		allUIDs[uid] = struct{}{}
	}
	for uid := range sMap {
		allUIDs[uid] = struct{}{}
	}

	var errs []string
	for uid := range allUIDs {
		if err := e.syncUID(ctx, uid, pMap, sMap); err != nil {
			log.Printf("sync: uid %s: %v", uid, err)
			errs = append(errs, uid)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("sync completed with %d errors (UIDs: %s)",
			len(errs), strings.Join(errs, ", "))
	}

	log.Printf("sync: done. %d Proton, %d Synology contacts.",
		len(pContacts), len(sContacts))
	return nil
}

func (e *Engine) syncUID(
	ctx context.Context,
	uid string,
	pMap map[string]proton.Contact,
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

	case pChanged && !sChanged, inProton && !inSynology:
		log.Printf("sync: uid %s: Proton -> Synology", uid)
		etag, err := e.synology.PutContact(ctx, uid, pc.VCard)
		if err != nil {
			return fmt.Errorf("put synology: %w", err)
		}
		return e.cache.Upsert(cache.ContactState{
			UID: uid, ProtonETag: pc.ETag, SynologyETag: etag, SyncedAt: time.Now(),
		})

	case sChanged && !pChanged, inSynology && !inProton:
		log.Printf("sync: uid %s: Synology -> Proton", uid)
		created, err := e.proton.CreateContact(ctx, sc.VCard)
		if err != nil {
			return fmt.Errorf("create proton: %w", err)
		}
		return e.cache.Upsert(cache.ContactState{
			UID: uid, ProtonETag: created.ETag, SynologyETag: sc.ETag, SyncedAt: time.Now(),
		})

	case !inProton && inSynology && !firstSeen:
		log.Printf("sync: uid %s: deleted on Proton -> delete on Synology", uid)
		if err := e.synology.DeleteContact(ctx, uid); err != nil {
			return err
		}
		return e.cache.Delete(uid)

	case inProton && !inSynology && !firstSeen:
		log.Printf("sync: uid %s: deleted on Synology -> delete on Proton", uid)
		if err := e.proton.DeleteContact(ctx, pc.ProtonID); err != nil {
			return err
		}
		return e.cache.Delete(uid)

	default:
		return nil
	}
}

func (e *Engine) handleConflict(
	ctx context.Context,
	uid string,
	pc proton.Contact,
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
		updated, err := e.proton.UpdateContact(ctx, pc.ProtonID, sc.VCard)
		if err != nil {
			return err
		}
		return e.cache.Upsert(cache.ContactState{
			UID: uid, ProtonETag: updated.ETag, SynologyETag: sc.ETag, SyncedAt: time.Now(),
		})

	default: // duplicate
		log.Printf("sync: uid %s: conflict -> duplicate", uid)
		pDupUID := uid + "-conflict-proton"
		pDupVCard := appendConflictSuffix(pc.VCard, pDupUID, "-conflict-proton")
		sETag1, err := e.synology.PutContact(ctx, pDupUID, pDupVCard)
		if err != nil {
			return fmt.Errorf("dup proton->synology: %w", err)
		}
		sDupUID := uid + "-conflict-synology"
		sDupVCard := appendConflictSuffix(sc.VCard, sDupUID, "-conflict-synology")
		sDupCreated, err := e.proton.CreateContact(ctx, sDupVCard)
		if err != nil {
			return fmt.Errorf("dup synology->proton: %w", err)
		}
		_ = e.cache.Upsert(cache.ContactState{
			UID: pDupUID, ProtonETag: pc.ETag, SynologyETag: sETag1, SyncedAt: time.Now(),
		})
		_ = e.cache.Upsert(cache.ContactState{
			UID: sDupUID, ProtonETag: sDupCreated.ETag, SynologyETag: sc.ETag, SyncedAt: time.Now(),
		})
		return e.cache.Upsert(cache.ContactState{
			UID: uid, ProtonETag: pc.ETag, SynologyETag: sc.ETag, SyncedAt: time.Now(),
		})
	}
}

func appendConflictSuffix(vcBytes []byte, newUID, suffix string) []byte {
	dec := vcard.NewDecoder(bytes.NewReader(vcBytes))
	card, err := dec.Decode()
	if err != nil {
		return vcBytes
	}
	card.SetValue(vcard.FieldUID, newUID)
	if f := card.Get(vcard.FieldFormattedName); f != nil {
		f.Value += suffix
	}
	var buf bytes.Buffer
	_ = vcard.NewEncoder(&buf).Encode(card)
	return buf.Bytes()
}
