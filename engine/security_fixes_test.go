package engine

import (
	"testing"
)

func TestPlanTestsHandlesNonPositiveMaxMutations(t *testing.T) {
	prepared := []preparedRequest{{Req: Request{URL: "https://example.test/orders/1", Method: "GET"}, Refs: []ObjectRef{{Kind: "numeric-id", Value: "1", Source: "url", Location: "url"}}}}
	actors := []Actor{
		{Name: "alice", User: "alice"},
		{Name: "bob", User: "bob"},
	}
	learned := []learnedObject{{Value: "1", Kind: "numeric-id", Actor: actors[0], Endpoint: EndpointSignature("GET", prepared[0].Req.URL, prepared[0].Refs)}}
	_ = PlanTests(prepared, nil, learned, actors, 0)
	_ = PlanTests(prepared, nil, learned, actors, -1)
}

func TestReplaceValueDoesNotCorruptUnrelatedURLData(t *testing.T) {
	req := Request{URL: "https://api.example.com/v1/users/1/profile?since=100&page=1"}
	got := replaceValue(req, "1", "999999")
	want := "https://api.example.com/v1/users/999999/profile?since=100&page=1"
	if got.URL != want {
		t.Fatalf("unexpected mutated URL: %s", got.URL)
	}
}

func TestReplaceValueTargetsObjectFieldsInJSON(t *testing.T) {
	req := Request{
		URL:  "https://api.example.com/orders/42",
		Body: `{"order_id":42,"page":42,"nested":{"user_id":42},"note":"order 42"}`,
	}
	got := replaceValue(req, "42", "99")
	want := `{"order_id":99,"page":42,"nested":{"user_id":99},"note":"order 42"}`
	if got.Body != want {
		t.Fatalf("unexpected mutated JSON body: %s", got.Body)
	}
}
