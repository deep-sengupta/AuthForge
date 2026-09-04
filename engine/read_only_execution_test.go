package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReadOnlyExecutionSkipsMutatingBaselineRequests(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	prepared := []preparedRequest{{Req: Request{URL: server.URL + "/orders/1", Method: http.MethodDelete}}}
	actors := []Actor{{Name: "alice"}}
	client := Client{Timeout: time.Second}

	obs, access := collectBaseline(prepared, Config{DenyStatuses: []int{401, 403, 404}}, actors, client, 1, false)
	if calls != 0 {
		t.Fatalf("read-only execution made %d mutating baseline requests", calls)
	}
	if len(obs) != 0 || len(access) != 0 {
		t.Fatalf("read-only execution retained a skipped mutation: observations=%d access=%d", len(obs), len(access))
	}
}
