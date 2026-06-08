package sync

import (
	"bytes"
	"strings"
	"testing"

	vcard "github.com/emersion/go-vcard"
)

// TestAppendConflictSuffix verifies that appendConflictSuffix correctly rewrites
// the UID and FN fields of a vCard without touching any other fields.
func TestAppendConflictSuffix(t *testing.T) {
	original := buildVCard(t, "uid-original", "Alice Example")

	result := appendConflictSuffix(original, "uid-conflict", "-conflict-proton")

	card, err := vcard.NewDecoder(bytes.NewReader(result)).Decode()
	if err != nil {
		t.Fatalf("decode result vCard: %v", err)
	}

	if uid := card.Value(vcard.FieldUID); uid != "uid-conflict" {
		t.Errorf("UID: want %q got %q", "uid-conflict", uid)
	}
	if fn := card.Value(vcard.FieldFormattedName); !strings.HasSuffix(fn, "-conflict-proton") {
		t.Errorf("FN %q should end with '-conflict-proton'", fn)
	}
	if !strings.HasPrefix(card.Value(vcard.FieldFormattedName), "Alice Example") {
		t.Errorf("FN %q should still start with 'Alice Example'", card.Value(vcard.FieldFormattedName))
	}
}

// TestAppendConflictSuffixBadInput verifies that a malformed vCard is returned
// unchanged rather than causing a panic.
func TestAppendConflictSuffixBadInput(t *testing.T) {
	bad := []byte("this is not a vcard")
	out := appendConflictSuffix(bad, "uid-x", "-suffix")
	if !bytes.Equal(out, bad) {
		t.Error("bad input should be returned unchanged")
	}
}

// buildVCard constructs a minimal valid vCard 4.0 for use in tests.
func buildVCard(t *testing.T, uid, fn string) []byte {
	t.Helper()
	card := vcard.Card{}
	card.SetValue(vcard.FieldVersion, "4.0")
	card.SetValue(vcard.FieldUID, uid)
	card.SetValue(vcard.FieldFormattedName, fn)
	var buf bytes.Buffer
	if err := vcard.NewEncoder(&buf).Encode(card); err != nil {
		t.Fatalf("encode test vCard: %v", err)
	}
	return buf.Bytes()
}
