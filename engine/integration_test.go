package engine

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func burpRequest(url, method string) string {
	raw := method + " / HTTP/1.1\r\nHost: test\r\n\r\n"
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func TestVerifiedBOLAEndToEnd(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/orders/")
		user := r.Header.Get("X-User")
		allowed := (user == "alice" && id == "1") || (user == "bob" && (id == "1" || id == "2"))
		if !allowed {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + id + `","name":"order"}`))
	})
	server := httptest.NewServer(h)
	defer server.Close()

	items := []BurpItem{
		{URL: server.URL + "/orders/1", Method: "GET", Request: burpRequest(server.URL+"/orders/1", "GET"), Mimetype: "JSON"},
		{URL: server.URL + "/orders/2", Method: "GET", Request: burpRequest(server.URL+"/orders/2", "GET"), Mimetype: "JSON"},
	}
	cfg := Config{
		FilterMimeTypes: []string{"JSON"},
		Actors: []Actor{
			{Name: "alice", Role: "user", User: "alice", Tenant: "tenant-a", Headers: map[string]string{"X-User": "alice"}},
			{Name: "bob", Role: "user", User: "bob", Tenant: "tenant-a", Headers: map[string]string{"X-User": "bob"}},
		},
		DenyStatuses: []int{401, 403, 404}, MaxMutations: 8,
	}

	dir := t.TempDir()
	result, err := Run(items, cfg, Options{Threads: 2, Timeout: 2_000_000_000, ExecuteTests: true, JSONPath: filepath.Join(dir, "report.json"), ReportPath: filepath.Join(dir, "report.html"), BaselinePath: filepath.Join(dir, "baseline.json")})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	verified := 0
	for _, f := range result.Report.Findings {
		if f.Type == "Verified BOLA/IDOR" && f.Verified {
			verified++
			if len(f.Evidence) < 4 {
				t.Fatalf("verified finding lacks proof evidence: %#v", f)
			}
		}
	}
	if verified == 0 {
		t.Fatalf("expected a verified BOLA, findings=%#v", result.Report.Findings)
	}
	if _, err := os.Stat(filepath.Join(dir, "baseline.json")); err != nil {
		t.Fatalf("baseline not written: %v", err)
	}
}

func TestSecureEndpointDoesNotProduceVerifiedBOLA(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/orders/")
		user := r.Header.Get("X-User")
		allowed := (user == "alice" && id == "1") || (user == "bob" && id == "2")
		if !allowed {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + id + `","name":"order"}`))
	})
	server := httptest.NewServer(h)
	defer server.Close()

	items := []BurpItem{
		{URL: server.URL + "/orders/1", Method: "GET", Request: burpRequest(server.URL+"/orders/1", "GET"), Mimetype: "JSON"},
		{URL: server.URL + "/orders/2", Method: "GET", Request: burpRequest(server.URL+"/orders/2", "GET"), Mimetype: "JSON"},
	}
	cfg := Config{
		FilterMimeTypes: []string{"JSON"},
		Actors: []Actor{
			{Name: "alice", Role: "user", User: "alice", Tenant: "tenant-a", Headers: map[string]string{"X-User": "alice"}},
			{Name: "bob", Role: "user", User: "bob", Tenant: "tenant-a", Headers: map[string]string{"X-User": "bob"}},
		},
		DenyStatuses: []int{401, 403, 404}, MaxMutations: 8,
	}

	result, err := Run(items, cfg, Options{Threads: 2, Timeout: 2_000_000_000, ExecuteTests: true})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	for _, f := range result.Report.Findings {
		if f.Type == "Verified BOLA/IDOR" && f.Verified {
			t.Fatalf("secure endpoint produced a verified BOLA: %#v", f)
		}
	}
}

func TestDryRunDoesNotExecuteMutations(t *testing.T) {
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	})
	server := httptest.NewServer(h)
	defer server.Close()
	items := []BurpItem{{URL: server.URL + "/orders/1", Method: "DELETE", Request: burpRequest(server.URL+"/orders/1", "DELETE"), Mimetype: "JSON", Status: 200}}
	cfg := Config{FilterMimeTypes: []string{"JSON"}, AutoDiscoverActors: true, ExecuteTests: false, AllowMutations: false, DenyStatuses: []int{401, 403, 404}, MaxMutations: 4}
	result, err := Run(items, cfg, Options{})
	if err == nil && result.Report.Stats["execution_enabled"] != 0 {
		t.Fatal("dry-run unexpectedly enabled")
	}
	if calls != 0 {
		t.Fatalf("dry-run made %d live requests", calls)
	}
}
