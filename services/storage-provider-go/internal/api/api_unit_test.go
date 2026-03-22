package api

import (
    "bytes"
    "context"
    "net/http"
    "net/http/httptest"
    "testing"

    "upspa/internal/model"
)

// Default mocked dependencies
type FakeStore struct {
    setups map[string]*model.SetupResponse
    records map[string]*model.RecordResponse
    pwds map[string]uint64
    kis map[string]string
}

func NewFakeStore() *FakeStore {
    return &FakeStore{
        setups: make(map[string]*model.SetupResponse),
        records: make(map[string]*model.RecordResponse),
        pwds: make(map[string]uint64),
        kis: make(map[string]string),
    }
}

func (s *FakeStore) PutSetup(ctx context.Context, uid, sigPk, cidNonce, cidCt, cidTag, kI string) (bool, error) {
    if _, ok := s.setups[uid]; ok {
        return false, nil // Idempotent
    }
    s.setups[uid] = &model.SetupResponse{
        UIDB64: uid,
        SigPkB64: sigPk,
        CID: model.CtBlob{Nonce: cidNonce, Ct: cidCt, Tag: cidTag},
    }
    s.kis[uid] = kI
    return true, nil
}

func (s *FakeStore) GetSetup(ctx context.Context, uid string) (*model.SetupResponse, error) {
    if val, ok := s.setups[uid]; ok {
        return val, nil
    }
    return nil, ErrNotFound
}

func (s *FakeStore) GetKi(ctx context.Context, uid string) (string, error) {
    if val, ok := s.kis[uid]; ok {
        return val, nil
    }
    return "", ErrNotFound
}

func (s *FakeStore) PutRecord(ctx context.Context, suid, cjNonce, cjCt, cjTag string) (bool, error) {
    if _, ok := s.records[suid]; ok {
        return false, ErrConflict
    }
    s.records[suid] = &model.RecordResponse{
        SUIDB64: suid,
        CJ: model.CtBlob{Nonce: cjNonce, Ct: cjCt, Tag: cjTag},
    }
    return true, nil
}

func (s *FakeStore) GetRecord(ctx context.Context, suid string) (*model.RecordResponse, error) {
    if val, ok := s.records[suid]; ok {
        return val, nil
    }
    return nil, ErrNotFound
}

func (s *FakeStore) UpdateRecord(ctx context.Context, suid, cjNonce, cjCt, cjTag string) error {
    if _, ok := s.records[suid]; !ok {
        return ErrNotFound
    }
    s.records[suid].CJ = model.CtBlob{Nonce: cjNonce, Ct: cjCt, Tag: cjTag}
    return nil
}

func (s *FakeStore) DeleteRecord(ctx context.Context, suid string) error {
    if _, ok := s.records[suid]; !ok {
        return ErrNotFound
    }
    delete(s.records, suid)
    return nil
}

func (s *FakeStore) GetPasswordUpdateState(ctx context.Context, uid string) (string, uint64, error) {
    setup, ok := s.setups[uid]
    if !ok {
        return "", 0, ErrNotFound
    }
    return setup.SigPkB64, s.pwds[uid], nil
}

func (s *FakeStore) PutPasswordUpdate(ctx context.Context, uid, newCidNonce, newCidCt, newCidTag, newKi string, newTimestamp uint64) error {
    s.pwds[uid] = newTimestamp
    s.kis[uid] = newKi
    s.setups[uid].CID = model.CtBlob{Nonce: newCidNonce, Ct: newCidCt, Tag: newCidTag}
    return nil
}


func TestSetupGet_NotFound(t *testing.T) {
    store := NewFakeStore()
    handler := NewHandler(store)
    
    req := httptest.NewRequest("GET", "/v1/setup/dummy_dummy_dummy_dummy_dummy_dummy", nil)
    req.SetPathValue("uid_b64", "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw") // 32 bytes valid base64
    
    rr := httptest.NewRecorder()
    handler.SetupGet(rr, req)
    
    if rr.Code != http.StatusNotFound {
        t.Errorf("expected 404 Not Found, got %d", rr.Code)
    }
}

func TestSetupGet_BadRequestMalformedBase64(t *testing.T) {
    store := NewFakeStore()
    handler := NewHandler(store)
    
    req := httptest.NewRequest("GET", "/v1/setup/inv!alid", nil)
    req.SetPathValue("uid_b64", "inv!alid") // invalid base64 and length
    
    rr := httptest.NewRecorder()
    handler.SetupGet(rr, req)
    
    if rr.Code != http.StatusBadRequest {
        t.Errorf("expected 400 Bad Request, got %d", rr.Code)
    }
}

func TestRecordCreate_Conflict(t *testing.T) {
    store := NewFakeStore()
    handler := NewHandler(store)

    // Base64URL no padding
    // 32 bytes = 43 chars
    suid := "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" 
    // 24 bytes = 32 chars
    nonce := "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
    // 40 bytes = 54 chars
    ct := "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
    // 16 bytes = 22 chars
    tag := "qqqqqqqqqqqqqqqqqqqqqq"

    store.PutRecord(context.Background(), suid, "nonce", "ct", "tag") // preload

    body := `{"suid_b64":"` + suid + `","cj":{"nonce":"` + nonce + `","ct":"` + ct + `","tag":"` + tag + `"}}`

    req := httptest.NewRequest("POST", "/v1/records", bytes.NewBufferString(body))
    req.Header.Set("Content-Type", "application/json")
    
    rr := httptest.NewRecorder()
    handler.RecordCreate(rr, req)
    
    if rr.Code != http.StatusConflict {
        t.Errorf("expected 409 Conflict, got %d", rr.Code)
    }
}

func TestSetupCreate_Success(t *testing.T) {
    store := NewFakeStore()
    handler := NewHandler(store)
    
    // Exact lengths required by validation:
    // uid_b64: 32, sig_pk_b64: 32, cid_nonce: 24, cid_ct: 96, cid_tag: 16, k_i_b64: 32
    body := `{
        "uid_b64":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw",
        "sig_pk_b64":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw",
        "cid":{
            "nonce":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw",
            "ct":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "tag":"qqqqqqqqqqqqqqqqqqqqqw"
        },
        "k_i_b64":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw"
    }`
    
    req := httptest.NewRequest("POST", "/v1/setup", bytes.NewBufferString(body))
    req.Header.Set("Content-Type", "application/json")
    
    rr := httptest.NewRecorder()
    handler.Setup(rr, req)
    
    if rr.Code != http.StatusCreated {
        t.Errorf("expected 201 Created, got %d", rr.Code)
    }
}