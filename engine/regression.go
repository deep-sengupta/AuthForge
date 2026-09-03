package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

func LoadBaseline(path string) (RegressionBaseline, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RegressionBaseline{}, err
	}
	var x RegressionBaseline
	if err := json.Unmarshal(b, &x); err != nil {
		return x, err
	}
	return x, nil
}

func BuildInvariants(obs []Observation) []AuthorizationInvariant {
	seen := map[string]AuthorizationInvariant{}
	for _, o := range obs {
		if o.Allowed == nil {
			continue
		}
		for _, obj := range o.Objects {
			k := invariantKey(o, obj.Value)
			seen[k] = AuthorizationInvariant{Key: k, Actor: o.Actor.Name, Role: o.Actor.Role, User: o.Actor.User, Tenant: o.Actor.Tenant, Method: o.Method, Endpoint: o.Endpoint, Action: o.Action, Object: obj.Value, Expected: *o.Allowed, Source: "observed-baseline"}
		}
		if len(o.Objects) == 0 {
			k := invariantKey(o, "")
			seen[k] = AuthorizationInvariant{Key: k, Actor: o.Actor.Name, Role: o.Actor.Role, User: o.Actor.User, Tenant: o.Actor.Tenant, Method: o.Method, Endpoint: o.Endpoint, Action: o.Action, Expected: *o.Allowed, Source: "observed-baseline"}
		}
	}
	out := make([]AuthorizationInvariant, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func CompareBaseline(base RegressionBaseline, current []Observation) []Finding {
	old := map[string]AuthorizationInvariant{}
	for _, inv := range base.Invariants {
		old[inv.Key] = inv
	}
	out := []Finding{}
	for _, o := range current {
		if o.Allowed == nil {
			continue
		}
		objs := o.Objects
		if len(objs) == 0 {
			objs = []ObjectRef{{Value: ""}}
		}
		for _, obj := range objs {
			k := invariantKey(o, obj.Value)
			bi, ok := old[k]
			if !ok {
				continue
			}
			if !bi.Expected && *o.Allowed {
				out = append(out, Finding{ID: newID(), Type: "Authorization regression", Severity: "high", Confidence: 96, Verified: true, Title: "Authorization invariant regressed", Summary: "An actor that was previously denied this exact authorization boundary is now allowed.", URL: o.URL, Endpoint: o.Endpoint, Method: o.Method, SourceActor: o.Actor, TargetActor: o.Actor, SourceObject: obj.Value, Evidence: []string{fmt.Sprintf("baseline expected=denied; current=allowed"), fmt.Sprintf("endpoint=%s", o.Endpoint), fmt.Sprintf("invariant=%s", bi.Key)}, ExploitChain: []string{o.Actor.Name + " → " + o.Endpoint + " → previously denied", o.Actor.Name + " → same boundary → now allowed"}, Recommendations: []string{"Restore object/route authorization checks", "Add this invariant to CI as a release gate"}})
			}
		}
	}
	return dedupeFindings(out)
}

func invariantKey(o Observation, object string) string {
	return strings.Join([]string{o.Actor.Name, o.Actor.Role, o.Actor.Tenant, o.Method, o.Endpoint, o.Action, object}, "|")
}
