// TODO(UPSPA-SP): Implement this file.
// - Read: docs/apis.md and docs/openapi/sp.yaml (wire contract)
// - Enforce: base64url-no-pad canonicalization + fixed-length checks
// - Never log secrets (uid/suid/cid/cj/k_i/signatures/points)
package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

func (s *Store) PutSetup(ctx context.Context, uid, sigPk, cidNonce, cidCt, cidTag, kI string) (bool, error) {
	const q = `
		INSERT INTO setup (uid_b64, sig_pk_b64, cid_nonce_b64, cid_ct_b64, cid_tag_b64, k_i_b64)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (uid_b64) DO NOTHING
	`
	tag, err := s.pool.Exec(ctx, q, uid, sigPk, cidNonce, cidCt, cidTag, kI)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) GetSetup(ctx context.Context, uid string) (sigPk, cidNonce, cidCt, cidTag, kI string, lastTs int64, found bool, err error) {
	const q = `
		SELECT sig_pk_b64, cid_nonce_b64, cid_ct_b64, cid_tag_b64, k_i_b64, last_pwd_update_time
		FROM setup
		WHERE uid_b64 = $1
	`
	err = s.pool.QueryRow(ctx, q, uid).Scan(&sigPk, &cidNonce, &cidCt, &cidTag, &kI, &lastTs)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", "", "", 0, false, nil
	}
	if err != nil {
		return "", "", "", "", "", 0, false, err
	}
	return sigPk, cidNonce, cidCt, cidTag, kI, lastTs, true, nil
}

func (s *Store) GetKi(ctx context.Context, uid string) (string, bool, error) {
	const q = `SELECT k_i_b64 FROM setup WHERE uid_b64 = $1`
	var kI string
	err := s.pool.QueryRow(ctx, q, uid).Scan(&kI)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return kI, true, nil
}

func (s *Store) CreateRecord(ctx context.Context, suid, cjNonce, cjCt, cjTag string) (bool, error) {
	const q = `
		INSERT INTO records (suid_b64, cj_nonce_b64, cj_ct_b64, cj_tag_b64)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (suid_b64) DO NOTHING
	`
	tag, err := s.pool.Exec(ctx, q, suid, cjNonce, cjCt, cjTag)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) GetRecord(ctx context.Context, suid string) (cjNonce, cjCt, cjTag string, found bool, err error) {
	const q = `
		SELECT cj_nonce_b64, cj_ct_b64, cj_tag_b64
		FROM records
		WHERE suid_b64 = $1
	`
	err = s.pool.QueryRow(ctx, q, suid).Scan(&cjNonce, &cjCt, &cjTag)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	return cjNonce, cjCt, cjTag, true, nil
}
func (s *Store) UpdateRecord(ctx context.Context, suid, cjNonce, cjCt, cjTag string) (bool, error) {
	const q = `
		UPDATE records
		SET cj_nonce_b64 = $2, cj_ct_b64 = $3, cj_tag_b64 = $4
		WHERE suid_b64 = $1
	`
	tag, err := s.pool.Exec(ctx, q, suid, cjNonce, cjCt, cjTag)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) DeleteRecord(ctx context.Context, suid string) (bool, error) {
	const q = `DELETE FROM records WHERE suid_b64 = $1`
	tag, err := s.pool.Exec(ctx, q, suid)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
func (s *Store) ApplyPasswordUpdate(ctx context.Context, uid string, ts int64, cidNonceNew, cidCtNew, cidTagNew, kINew string) (bool, error) {
	const q = `
		UPDATE setup
		SET
			cid_nonce_b64 = $3,
			cid_ct_b64 = $4,
			cid_tag_b64 = $5,
			k_i_b64 = $6,
			last_pwd_update_time = $2
		WHERE uid_b64 = $1
		  AND $2 > last_pwd_update_time
	`
	tag, err := s.pool.Exec(ctx, q, uid, ts, cidNonceNew, cidCtNew, cidTagNew, kINew)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
