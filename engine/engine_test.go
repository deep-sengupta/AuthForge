package engine

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAutoDiscoverActorsFromJWTAndHeaders(t *testing.T) {
	tok := func(sub, role, tenant string) string {
		enc := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }
		return enc(`eyJhbGciOiJub25lIn0`) + "." + enc(`{"sub":"`+sub+`","role":"`+role+`","tenant_id":"`+tenant+`"}`) + ".x"
	}
	items := []BurpItem{
		{Request: base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + tok("alice", "admin", "t1") + "\r\n\r\n"))},
		{Request: base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + tok("bob", "user", "t2") + "\r\n\r\n"))},
	}
	actors := DiscoverActors(items)
	if len(actors) != 2 || actors[0].User == "" || actors[0].Role == "unknown" || actors[0].Tenant == "" {
		t.Fatalf("unexpected actors: %#v", actors)
	}
}

func TestEnrichActorsFromTraffic(t *testing.T) {
	tok := "Bearer raw-user-a"
	items := []BurpItem{{Request: base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: " + tok + "\r\nX-Role: admin\r\nX-Tenant-ID: t1\r\n\r\n"))}}
	actors := EnrichActorsFromTraffic([]Actor{{Name: "a", Headers: map[string]string{"Authorization": tok}}}, items)
	if actors[0].Role != "admin" || actors[0].Tenant != "t1" {
		t.Fatalf("actor metadata was not inferred: %#v", actors[0])
	}
}

func TestDiscoverObjects(t *testing.T) {
	refs := DiscoverObjects("https://example.test/api/users/42/orders/550e8400-e29b-41d4-a716-446655440000", `{"tenant_id":7}`, nil)
	if len(refs) < 3 {
		t.Fatalf("expected >=3 object refs, got %d", len(refs))
	}
}

func TestMutations(t *testing.T) {
	got := GenerateMutations(ObjectRef{Kind: "numeric-id", Value: "10"}, Actor{User: "bob"})
	if len(got) < 4 {
		t.Fatalf("expected mutations, got %v", got)
	}
}

func TestBehavioralSimilarity(t *testing.T) {
	h := http.Header{"Content-Type": []string{"application/json"}, "X-Test": []string{"1"}}
	a := FingerprintBytes(200, h, nil, 100, []byte(`{"id":10,"name":"alice"}`))
	b := FingerprintBytes(200, h, nil, 120, []byte(`{"id":11,"name":"bob"}`))
	if Similar(a, b) < 0.65 {
		t.Fatalf("expected behaviorally similar responses")
	}
}

func TestDOTIncludesAllowedSignalAndAttackPath(t *testing.T) {
	allowed := true
	g := BuildGraph([]Observation{{Actor: Actor{Name: "a", Role: "user", User: "alice"}, Method: "GET", URL: "https://x.test/o/1", Action: "read", Objects: []ObjectRef{{Value: "1"}}, Allowed: &allowed, Fingerprint: ResponseFingerprint{Status: 200}, Timestamp: time.Now()}})
	f := Finding{ID: "f1", Title: "Verified", Confidence: 96, Verified: true, ExploitChain: []string{"alice -> object 1", "bob -> object 1 -> VERIFIED"}}
	g = AddFindingPaths(g, []Finding{f})
	dot := GraphDOT(g)
	if !strings.Contains(dot, "allowed=true") || !strings.Contains(dot, "attack-step") {
		t.Fatalf("DOT lost graph state/path data: %s", dot)
	}
}

func TestGraph(t *testing.T) {
	allowed := true
	g := BuildGraph([]Observation{{Actor: Actor{Name: "a", Role: "user", User: "alice"}, Method: "GET", URL: "https://x.test/o/1", Action: "read", Objects: []ObjectRef{{Value: "1"}}, Allowed: &allowed, Fingerprint: ResponseFingerprint{Status: 200}, Timestamp: time.Now()}})
	if len(g.Nodes) < 4 || len(g.Edges) < 3 {
		t.Fatalf("graph too small: %#v", g)
	}
}

func TestBuildInvariantsAndRegression(t *testing.T) {
	denied := false
	allowed := true
	baseObs := []Observation{{Actor: Actor{Name: "guest", Role: "guest"}, Method: "GET", URL: "https://x.test/orders/1", Endpoint: "GET /orders/{object}", Action: "read", Objects: []ObjectRef{{Value: "1"}}, Allowed: &denied}}
	curObs := []Observation{{Actor: Actor{Name: "guest", Role: "guest"}, Method: "GET", URL: "https://x.test/orders/1", Endpoint: "GET /orders/{object}", Action: "read", Objects: []ObjectRef{{Value: "1"}}, Allowed: &allowed}}
	base := RegressionBaseline{Invariants: BuildInvariants(baseObs)}
	findings := CompareBaseline(base, curObs)
	if len(findings) != 1 || !findings[0].Verified {
		t.Fatalf("expected verified regression, got %#v", findings)
	}
}

func TestFindPreparedPrefersExactURLBeforeEndpointFallback(t *testing.T) {
	prepared := []preparedRequest{
		{Req: Request{Method: "GET", URL: "https://x.test/orders/111"}, Refs: []ObjectRef{{Value: "111", Kind: "numeric-id"}}},
		{Req: Request{Method: "GET", URL: "https://x.test/orders/222"}, Refs: []ObjectRef{{Value: "222", Kind: "numeric-id"}}},
		{Req: Request{Method: "GET", URL: "https://x.test/orders/333"}, Refs: []ObjectRef{{Value: "333", Kind: "numeric-id"}}},
	}
	endpoint := EndpointSignature("GET", "https://x.test/orders/222", prepared[1].Refs)
	got, ok := findPrepared(prepared, endpoint, "https://x.test/orders/222", "GET")
	if !ok {
		t.Fatal("expected exact URL request to be found")
	}
	if got.Req.URL != "https://x.test/orders/222" || got.Refs[0].Value != "222" {
		t.Fatalf("exact URL match was not preferred: %#v", got)
	}
}

func TestEndpointSignatureGeneralizesPathObjects(t *testing.T) {
	got := EndpointSignature("GET", "https://x.test/api/orders/123/items/456", nil)
	want := "GET /api/orders/{object}/items/{object}"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDiscoverObjectsIgnoresURLHostPort(t *testing.T) {
	refs := DiscoverObjects("http://127.0.0.1:54321/orders/1", "", nil)
	for _, r := range refs {
		if r.Value == "127" || r.Value == "54321" {
			t.Fatalf("host/port leaked into object discovery: %#v", refs)
		}
	}
	found := false
	for _, r := range refs {
		if r.Value == "1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected order id 1, got %#v", refs)
	}
}

func TestYAMLGlobalHeaderUnquotesFirstListValue(t *testing.T) {
	cfg, err := parseConfigYAML("source: capture.xml\nheaders:\n  - User-Agent: \"AuthForge/\"\n")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if got := cfg.GlobalHeaders[0]["User-Agent"]; got != "AuthForge/" {
		t.Fatalf("header was not unquoted: %q", got)
	}
}

func TestEnrichActorsFromTrafficReturnsUnion(t *testing.T) {
	mkReq := func(auth, role, tenant string) BurpItem {
		raw := "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: " + auth + "\r\nX-Role: " + role + "\r\nX-Tenant-ID: " + tenant + "\r\n\r\n"
		return BurpItem{Request: base64.StdEncoding.EncodeToString([]byte(raw))}
	}
	items := []BurpItem{
		mkReq("Bearer explicit", "admin", "t1"),
		mkReq("Bearer discovered", "viewer", "t2"),
	}
	explicit := []Actor{{Name: "explicit", Headers: map[string]string{"Authorization": "Bearer explicit"}}}
	actors := EnrichActorsFromTraffic(explicit, items)
	if len(actors) != 2 {
		t.Fatalf("expected explicit + discovered actors, got %#v", actors)
	}
	foundDiscovered := false
	for _, a := range actors {
		if a.Role == "viewer" && a.Tenant == "t2" {
			foundDiscovered = true
		}
	}
	if !foundDiscovered {
		t.Fatalf("unmatched discovered actor was dropped: %#v", actors)
	}
}

func TestDOTEscapesLabels(t *testing.T) {
	allowed := true
	g := BuildGraph([]Observation{{Actor: Actor{Name: "a", Role: "qa\"role", User: "alice\"x"}, Method: "GET", URL: "https://x.test/o/1", Action: "re\"ad", Objects: []ObjectRef{{Value: "1\"2"}}, Allowed: &allowed}})
	dot := GraphDOT(g)
	if strings.Contains(dot, "label=\"qa\"role\"") || strings.Contains(dot, "label=\"1\"2\"") {
		t.Fatalf("DOT label remained structurally unsafe: %s", dot)
	}
}

func TestGraphPreservesAllowedAndDeniedEdges(t *testing.T) {
	allowed := true
	denied := false
	obs := []Observation{
		{Actor: Actor{Name: "a", Role: "user", User: "alice"}, Method: "GET", URL: "https://x.test/o/1", Action: "read", Objects: []ObjectRef{{Value: "1"}}, Allowed: &allowed},
		{Actor: Actor{Name: "a", Role: "user", User: "alice"}, Method: "GET", URL: "https://x.test/o/1", Action: "read", Objects: []ObjectRef{{Value: "1"}}, Allowed: &denied},
	}
	g := BuildGraph(obs)
	dot := GraphDOT(g)
	if !strings.Contains(dot, "allowed=true") || !strings.Contains(dot, "allowed=false") {
		t.Fatalf("graph lost one of the authorization states: %s", dot)
	}
}

func TestEnrichActorsFromTrafficDedupesCredentialWithExtraHeader(t *testing.T) {
	item := BurpItem{Request: base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer same-session\r\nX-Extra: explicit-only\r\nX-Role: admin\r\nX-Tenant-ID: t1\r\n\r\n"))}
	explicit := []Actor{{Name: "admin-alias", Headers: map[string]string{"Authorization": "Bearer same-session", "X-Extra": "explicit-only"}}}
	actors := EnrichActorsFromTraffic(explicit, []BurpItem{item})
	if len(actors) != 1 {
		t.Fatalf("same session was duplicated after discovery: %#v", actors)
	}
	if actors[0].Role != "admin" || actors[0].Tenant != "t1" {
		t.Fatalf("matching discovered metadata was not retained: %#v", actors[0])
	}
}

func TestActorIdentityKeyIgnoresNonCredentialHeaders(t *testing.T) {
	a := Actor{Headers: map[string]string{"Authorization": "Bearer same", "X-Role": "admin"}}
	b := Actor{Headers: map[string]string{"Authorization": "Bearer same", "X-Role": "viewer"}}
	if actorIdentityKey(a) != actorIdentityKey(b) {
		t.Fatalf("identity keys differ despite identical credential: %q vs %q", actorIdentityKey(a), actorIdentityKey(b))
	}
}
