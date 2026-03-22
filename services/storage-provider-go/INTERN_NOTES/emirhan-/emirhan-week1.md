# Week 1 Progress

## 1. Endpoint List
Here are the 5 main areas we are building:

| `GET`  | `/v1/health` | Check if server is running |
| `POST` | `/v1/setup` | Save a user's first cryptographic keys |
| `GET`  | `/v1/setup/{uid_b64}` | Fetch stored setup data |
| `POST` | `/v1/toprf/eval` | Do the TOPRF math for login (`y_i = blinded * k_i`) |
| `POST`, `GET`, `PUT`, `DELETE` | `/v1/records` | Create, read, update, or delete encrypted records |
| `POST` | `/v1/password-update` | Securely update the master password |

---

## 2. Details for Each Endpoint (Validations & Status Codes)


**`/v1/health`**
* **Validations:** None.
* **Success:** `200 OK` (Returns `{"ok": true}`)

**`/v1/setup`**
* **Validations:** `uid_b64` must be valid Base64. `sig_pk_b64` must be exactly 32 bytes. `cid` parts and `k_i_b64` must match exact byte lengths.
* **Success:** `201 Created` or `200 OK` (if already exists).
* **Errors:** `400 Bad Request` (wrong length/format), `409 Conflict`.

**`/v1/toprf/eval`**
* **Validations:** `blinded_b64` must be exactly 32 bytes and a valid canonical Ristretto point.
* **Success:** `200 OK` (Returns `y_b64`).
* **Errors:** `400 Bad Request`, `404 Not Found` (User doesn't exist).

**`/v1/records` (CRUD Operations)**
* **Validations:** `suid_b64` must be valid Base64. Payload `cj` lengths must be exact (nonce 24, ct 40, tag 16 bytes).
* **Success:** `201 Created` (POST), `200 OK` (GET/PUT/DELETE).
* **Errors:** `400 Bad Request`, `404 Not Found`, `409 Conflict` (If record already exists on POST).

**`/v1/password-update`**
* **Validations:** Timestamp must be strictly greater than the last update. Signature (`sig_b64`) MUST be exactly 64 bytes and mathematically verified using Ed25519.
* **Success:** `200 OK`.
* **Errors:** `400 Bad Request`, `401 Unauthorized` (Bad signature), `404 Not Found`, `409 Conflict` (Old timestamp).

---

## 3. Consistent JSON Error Shape
Instead of random error messages, I propose we use one standard format for all errors. This makes it easy for the frontend to read:

```json
{
  "error": {
    "code": "INVALID_BASE64",
    "message": "The uid_b64 field is not valid base64.",
    "details": {
      "field": "uid_b64"
    }
  }
}