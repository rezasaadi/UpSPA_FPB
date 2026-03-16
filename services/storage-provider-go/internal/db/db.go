// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)
package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context) (*Store, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL is not set")
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := applyMigrations(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}

	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	path := filepath.Join("internal", "db", "migrations", "001_init.sql")
	sqlBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}

	if _, err := pool.Exec(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("apply migration: %w", err)
	}

	return nil
}
