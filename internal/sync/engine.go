// Package sync implements the bidirectional sync engine between a Proton
// Bridge and a Synology CardDAV server.
//
// Conflict policy: "duplicate" (default)
//   When both sides changed the same UID since the last sync, both versions
//   are preserved.  The Synology copy gets a new UID with suffix
//   "-conflict-proton" appended to FN; the Proton copy gets
//   "-conflict-synology".  Both are written back to both sides.
package sync

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	vcard "github.com/emersion/go-vcard"

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

// NewEngine constructs an Engine from an already-authenticated Proton Bridge
// plus Synology CardDAV credentials. The Bridge is created by the caller via
// proton.NewClientAndBridge so that OTP prompting happens at the right layer.
func NewEngine(
	bridge *proton.Bridge,
	synologyURL, synologyBook, synologyUser, synologyPass string,
	conflictPolicy string,
) *Engine {
	sc := synology.NewClient(synologyURL, synologyBook, synologyUser, synologyPass)

	db, err := cache.Open("sync-cache.db")
	if err != nil {
		// Cache open failure is fatal: we cannot detect conflicts without it.
		panic(fmt.Sprintf("cache open: %v", err))
	}

	policy := conflictPolicy
	if policy == "" {
		policy = "duplicate"
	}

	return &Engine{
		proton:   bridge,
		synology: sc,
		cache:    db,
		policy:   policy,
	}
}

// Close releases the cache DB handle and logs out from Proton.
func (e *Engine) Close() {
	e.cache.Close()
	e.proton.Close(context.Background())
}

// SyncOnce performs one full bidirectional sync cycle.
func (e *Engine) SyncOnce(ctx context.Context) error {
	log.Println("sync: fetching contacts from Proton ...")
	// proton.Bridge.ListCards returns []proton.CardObject
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
		// Both sides changed independently since the last sync — conflict.
		return e.handleConflict(ctx, uid, pc, sc)

	case (pChanged && !sChanged) || (inProton && !inSynology):
		// Proton is newer or only exists on Proton — push to Synology.
		log.Printf("sync: uid %s: Proton -> Synology", uid)
		etag, err := e.synology.PutContact(ctx, uid, pc.VCard)
		if err != nil {
			return fmt.Errorf("put synology: %w", err)
		}
		return e.cache.Upsert(cache.ContactState{
			UID: uid, ProtonETag: pc.ETag, SynologyETag: etag, SyncedAt: time.Now(),
		})

	case (sChanged && !pChanged) || (inSynology && !inProton):
		// Synology is newer or only exists on Synology — push to Proton.
		log.Printf("sync: uid %s: Synology -> Proton", uid)
		// UpsertCardByVCard creates or updates on Proton side.
		obj, _, err := e.proton.UpsertCardByVCard(ctx, uid+".vcf", sc.VCard)
		if err != nil {
			return fmt.Errorf("upsert proton: %w", err)
		}
		return e.cache.Upsert(cache.ContactState{
			UID: uid, ProtonETag: obj.ETag, SynologyETag: sc.ETag, SyncedAt: time.Now(),
		})

	case !inProton && inSynology && !firstSeen:
		// Deleted on Proton since last sync — propagate deletion to Synology.
		log.Printf("sync: uid %s: deleted on Proton -> delete on Synology", uid)
		if err := e.synology.DeleteContact(ctx, uid); err != nil {
			return err
		}
		return e.cache.Delete(uid)

	case inProton && !inSynology && !firstSeen:
		// Deleted on Synology since last sync — propagate deletion to Proton.
		log.Printf("sync: uid %s: deleted on Synology -> delete on Proton", uid)
		if err := e.proton.DeleteCardByHref(ctx, pc.Href); err != nil {
			return err
		}
		return e.cache.Delete(uid)

	default:
		// Nothing changed on either side.
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

		// Create a duplicate of the Proton version on Synology.
		pDupUID := uid + "-conflict-proton"
		pDupVCard := appendConflictSuffix(pc.VCard, pDupUID, "-conflict-proton")
		sETag1, err := e.synology.PutContact(ctx, pDupUID, pDupVCard)
		if err != nil {
			return fmt.Errorf("dup proton->synology: %w", err)
		}
		// Create a duplicate of the Synology version on Proton.
		sDupUID := uid + "-conflict-synology"
		sDupVCard := appendConflictSuffix(sc.VCard, sDupUID, "-conflict-synology")
		pDupObj, _, err := e.proton.UpsertCardByVCard(ctx, sDupUID+".vcf", sDupVCard)
		if err != nil {
			return fmt.Errorf("dup synology->proton: %w", err)
		}
		// Cache both duplicates.
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
		// Remove the original conflicting entry from the cache so the
		// next sync treats the duplicates as canonical.
		return e.cache.Delete(uid)
	}
}

// appendConflictSuffix rewrites the UID and FN fields of a vCard to
// mark it as a conflict copy.
func appendConflictSuffix(vcBytes []byte, newUID, fnSuffix string) []byte {
	card, err := vcard.NewDecoder(bytes.NewReader(vcBytes)).Decode()
	if err != nil {
		// If we cannot parse the vCard, return it unchanged with a header comment.
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
