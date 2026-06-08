// Package cache provides a SQLite-backed local sync state store.
package cache

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS contacts (
	uid            TEXT PRIMARY KEY,
	proton_etag    TEXT NOT NULL DEFAULT '',
	synology_etag  TEXT NOT NULL DEFAULT '',
	synced_at      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

type DB struct {
	db *sql.DB
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("cache: open %s: %w", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("cache: init schema: %w", err)
	}
	return &DB{db: db}, nil
}

func (c *DB) Close() error { return c.db.Close() }

type ContactState struct {
	UID          string
	ProtonETag   string
	SynologyETag string
	SyncedAt     time.Time
}

func (c *DB) Get(uid string) (ContactState, error) {
	row := c.db.QueryRow(
		`SELECT uid, proton_etag, synology_etag, synced_at FROM contacts WHERE uid = ?`, uid)
	var s ContactState
	var ts int64
	err := row.Scan(&s.UID, &s.ProtonETag, &s.SynologyETag, &ts)
	if err == sql.ErrNoRows {
		return ContactState{UID: uid}, nil
	}
	if err != nil {
		return ContactState{}, err
	}
	s.SyncedAt = time.Unix(ts, 0)
	return s, nil
}

func (c *DB) Upsert(s ContactState) error {
	_, err := c.db.Exec(
		`INSERT INTO contacts (uid, proton_etag, synology_etag, synced_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(uid) DO UPDATE SET
		   proton_etag   = excluded.proton_etag,
		   synology_etag = excluded.synology_etag,
		   synced_at     = excluded.synced_at`,
		s.UID, s.ProtonETag, s.SynologyETag, s.SyncedAt.Unix(),
	)
	return err
}

func (c *DB) Delete(uid string) error {
	_, err := c.db.Exec(`DELETE FROM contacts WHERE uid = ?`, uid)
	return err
}

func (c *DB) All() ([]ContactState, error) {
	rows, err := c.db.Query(`SELECT uid, proton_etag, synology_etag, synced_at FROM contacts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ContactState
	for rows.Next() {
		var s ContactState
		var ts int64
		if err := rows.Scan(&s.UID, &s.ProtonETag, &s.SynologyETag, &ts); err != nil {
			return nil, err
		}
		s.SyncedAt = time.Unix(ts, 0)
		out = append(out, s)
	}
	return out, rows.Err()
}

func (c *DB) SetMeta(key, value string) error {
	_, err := c.db.Exec(
		`INSERT INTO meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (c *DB) GetMeta(key string) (string, error) {
	var v string
	err := c.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}
