// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)
package db

import (
	"context"
	"os"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL is not set")
	}

	store, err := New(context.Background())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}
func TestPutSetup_IdempotentBehavior(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	created, err := store.PutSetup(ctx, "u1", "sig1", "n1", "ct1", "tag1", "ki1")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected first insert to create row")
	}

	created, err = store.PutSetup(ctx, "u1", "sig1", "n1", "ct1", "tag1", "ki1")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("expected second insert to be ignored")
	}
}

func TestCreateRecord_Unique(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	created, err := store.CreateRecord(ctx, "r1", "n1", "ct1", "tag1")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected record creation")
	}

	created, err = store.CreateRecord(ctx, "r1", "n2", "ct2", "tag2")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("expected duplicate record to be ignored")
	}
}

func TestUpdateRecord_MissingReturnsFalse(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	updated, err := store.UpdateRecord(ctx, "missing", "n", "ct", "tag")
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Fatal("expected missing record update to return false")
	}
}

func TestApplyPasswordUpdate_ReplayRejected(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	_, err := store.PutSetup(ctx, "u2", "sig", "n1", "ct1", "tag1", "ki1")
	if err != nil {
		t.Fatal(err)
	}

	applied, err := store.ApplyPasswordUpdate(ctx, "u2", 10, "n2", "ct2", "tag2", "ki2")
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("expected first password update to apply")
	}

	applied, err = store.ApplyPasswordUpdate(ctx, "u2", 10, "n3", "ct3", "tag3", "ki3")
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		t.Fatal("expected replayed password update to be rejected")
	}
}
