package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// In Go, test functions always start with "Test" and take a (t *testing.T) parameter.
func TestHandleHealth(t *testing.T) {
	// STEP 1: Create a fake client request.
	// Prepare a GET request to "/v1/health" as if it came from the internet.
	req, err := http.NewRequest("GET", "/v1/health", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// STEP 2: Create a fake response container (Response Recorder).
	// The server will write the response to this recorder instead of the network.
	rr := httptest.NewRecorder()

	// STEP 3: Run the function under test.
	// No router is needed here; call handleHealth directly with the fake request and recorder.
	handleHealth(rr, req)

	// STEP 4: CHECK 1 - Is the status code correct?
	// We expect 200 OK.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Wrong status code returned! Expected: %v, Got: %v", http.StatusOK, status)
	}

	// STEP 5: CHECK 2 - Is the returned JSON text correct?
	// WriteJSON may append a trailing newline (\n).
	// Use strings.TrimSpace to remove it before comparing the actual content.
	expected := `{"ok":true}`
	actual := strings.TrimSpace(rr.Body.String())

	if actual != expected {
		t.Errorf("Wrong response body returned! Expected: %s, Got: %s", expected, actual)
	}
}