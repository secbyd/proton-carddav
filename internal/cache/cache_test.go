package cache

import (
	"os"
	"testing"
	"time"
)

// TestCacheRoundtrip opens a temporary SQLite DB, writes a ContactState,
// reads it back, updates it, and deletes it — exercising the full CRUD
// path without any network or Proton credentials.
func TestCacheRoundtrip(t *testing.T) {
	f, err := os.CreateTemp("", "cache-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	db, err := Open(f.Name())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	uid := "test-uid-1"
	now := time.Now().Truncate(time.Second)

	// Insert.
	if err := db.Upsert(ContactState{
		UID:          uid,
		ProtonETag:   "ptag1",
		SynologyETag: "stag1",
		SyncedAt:     now,
	}); err != nil {
		t.Fatalf("Upsert (insert): %v", err)
	}

	// Read back.
	got, err := db.Get(uid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ProtonETag != "ptag1" {
		t.Errorf("ProtonETag: want %q got %q", "ptag1", got.ProtonETag)
	}
	if got.SynologyETag != "stag1" {
		t.Errorf("SynologyETag: want %q got %q", "stag1", got.SynologyETag)
	}

	// Update.
	if err := db.Upsert(ContactState{
		UID:          uid,
		ProtonETag:   "ptag2",
		SynologyETag: "stag2",
		SyncedAt:     now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("Upsert (update): %v", err)
	}
	got, err = db.Get(uid)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if got.ProtonETag != "ptag2" {
		t.Errorf("updated ProtonETag: want %q got %q", "ptag2", got.ProtonETag)
	}

	// Delete.
	if err := db.Delete(uid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// After deletion Get should return a zero-value state, not an error.
	got, err = db.Get(uid)
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if !got.SyncedAt.IsZero() {
		t.Errorf("expected zero SyncedAt after delete, got %v", got.SyncedAt)
	}
}
