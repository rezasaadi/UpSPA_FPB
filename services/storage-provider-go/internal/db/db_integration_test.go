package db

import (
	"context"
	"os"
	"testing"

	"upspa/internal/testutil"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	ctx := context.Background()
	dsn := os.Getenv("DATABASE_URL")
	var cleanup func()
	if dsn == "" {
		var err error
		dsn, cleanup, err = testutil.StartPostgresContainer(ctx)
		if err != nil {
			t.Skipf("DATABASE_URL is not set and test Postgres is unavailable: %v", err)
		}
		t.Cleanup(cleanup)
	}

	store, err := NewWithDSN(ctx, dsn)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	if _, err := store.pool.Exec(ctx, `TRUNCATE records, setup`); err != nil {
		t.Fatalf("reset test database: %v", err)
	}

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

	sigPk, cidNonce, cidCt, cidTag, kI, lastTs, found, err := store.GetSetup(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected setup row to be found")
	}
	if sigPk != "sig1" || cidNonce != "n1" || cidCt != "ct1" || cidTag != "tag1" || kI != "ki1" || lastTs != 0 {
		t.Fatalf("unexpected setup row: sigPk=%q nonce=%q ct=%q tag=%q kI=%q lastTs=%d", sigPk, cidNonce, cidCt, cidTag, kI, lastTs)
	}

	gotKI, found, err := store.GetKi(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if !found || gotKI != "ki1" {
		t.Fatalf("expected k_i lookup to return ki1, found=%v got=%q", found, gotKI)
	}
}

func TestRecordCRUDAndUniqueness(t *testing.T) {
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

	cjNonce, cjCt, cjTag, found, err := store.GetRecord(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if cjNonce != "n1" || cjCt != "ct1" || cjTag != "tag1" {
		t.Fatalf("unexpected initial record values: nonce=%q ct=%q tag=%q", cjNonce, cjCt, cjTag)
	}

	updated, err := store.UpdateRecord(ctx, "r1", "n3", "ct3", "tag3")
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("expected existing record update to return true")
	}

	cjNonce, cjCt, cjTag, found, err = store.GetRecord(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected updated record to be found")
	}
	if cjNonce != "n3" || cjCt != "ct3" || cjTag != "tag3" {
		t.Fatalf("unexpected updated record values: nonce=%q ct=%q tag=%q", cjNonce, cjCt, cjTag)
	}

	deleted, err := store.DeleteRecord(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("expected existing record delete to return true")
	}

	_, _, _, found, err = store.GetRecord(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("expected deleted record to be missing")
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

	deleted, err := store.DeleteRecord(ctx, "missing")
	if err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Fatal("expected missing record delete to return false")
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

	_, cidNonce, cidCt, cidTag, kI, lastTs, found, err := store.GetSetup(ctx, "u2")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected setup row to still exist")
	}
	if cidNonce != "n2" || cidCt != "ct2" || cidTag != "tag2" || kI != "ki2" || lastTs != 10 {
		t.Fatalf("expected stored password-update values to remain at first update, got nonce=%q ct=%q tag=%q kI=%q ts=%d", cidNonce, cidCt, cidTag, kI, lastTs)
	}

	applied, err = store.ApplyPasswordUpdate(ctx, "u2", 11, "n4", "ct4", "tag4", "ki4")
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("expected newer password update to apply")
	}

	_, cidNonce, cidCt, cidTag, kI, lastTs, found, err = store.GetSetup(ctx, "u2")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected setup row to still exist after newer update")
	}
	if cidNonce != "n4" || cidCt != "ct4" || cidTag != "tag4" || kI != "ki4" || lastTs != 11 {
		t.Fatalf("expected stored password-update values to advance, got nonce=%q ct=%q tag=%q kI=%q ts=%d", cidNonce, cidCt, cidTag, kI, lastTs)
	}
}

func TestApplyPasswordUpdate_MissingSetupReturnsFalse(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	applied, err := store.ApplyPasswordUpdate(ctx, "missing", 10, "n", "ct", "tag", "ki")
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		t.Fatal("expected missing setup update to return false")
	}
}
