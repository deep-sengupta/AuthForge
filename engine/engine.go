package engine

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Proxy             string
	Threads           int
	Timeout           time.Duration
	InsecureTLS       bool
	VerifySideEffects bool
	BaselinePath      string
	ReportPath        string
	JSONPath          string
	CustomPatterns    []string
	MaxMutations      int
	ExecuteTests      bool
	AllowMutations    bool
}

type Result struct{ Report Report }

type preparedRequest struct {
	Item BurpItem
	Req  Request
	Refs []ObjectRef
}

type accessRecord struct {
	Observation Observation
	Body        string
}

type learnedObject struct {
	Value       string
	Kind        string
	Actor       Actor
	Endpoint    string
	Observation Observation
	Body        string
}

func Run(items []BurpItem, cfg Config, opt Options) (Result, error) {
	actors := cfg.Actors
	if cfg.AutoDiscoverActors {
		actors = EnrichActorsFromTraffic(actors, items)
	}
	if len(actors) == 0 {
		return Result{}, fmt.Errorf("no actors found; provide actors or enable autoDiscoverActors")
	}
	if opt.Threads < 1 {
		opt.Threads = 4
	}
	if opt.Timeout <= 0 {
		opt.Timeout = cfg.Timeout
	}
	if opt.MaxMutations <= 0 {
		opt.MaxMutations = cfg.MaxMutations
	}
	if !opt.VerifySideEffects {
		opt.VerifySideEffects = cfg.VerifySideEffects
	}
	if !opt.ExecuteTests {
		opt.ExecuteTests = cfg.ExecuteTests
	}
	if !opt.AllowMutations {
		opt.AllowMutations = cfg.AllowMutations
	}

	client := Client{Timeout: opt.Timeout, Proxy: opt.Proxy, InsecureTLS: opt.InsecureTLS}
	prepared := prepareRequests(items, cfg, opt)
	var observations []Observation
	var access map[string]accessRecord
	if opt.ExecuteTests {
		observations, access = collectBaseline(prepared, cfg, actors, client, opt.Threads, opt.AllowMutations)
	} else {
		observations, access = collectCapturedBaseline(prepared, actors, cfg)
	}
	learned := learnObjects(observations, access)
	tests := PlanTests(prepared, observations, learned, actors, opt.MaxMutations)
	findings := []Finding{}
	if opt.ExecuteTests {
		findings = executeTestCases(tests, prepared, access, cfg, actors, client, opt)
	}
	attackPaths := BuildAttackPaths(findings)
	graph := BuildGraph(observations)
	graph = AddFindingPaths(graph, findings)
	invariants := BuildInvariants(observations)

	report := Report{GeneratedAt: time.Now().UTC(), Version: "", Findings: findings, Graph: graph, Stats: map[string]int{}, Invariants: invariants, TestCases: tests, AttackPaths: attackPaths}
	report.Stats["requests"] = len(prepared)
	report.Stats["observations"] = len(observations)
	report.Stats["generated_tests"] = len(tests)
	report.Stats["learned_objects"] = len(learned)
	report.Stats["findings"] = len(findings)
	report.Stats["execution_enabled"] = boolInt(opt.ExecuteTests)
	report.Stats["mutations_enabled"] = boolInt(opt.AllowMutations && opt.ExecuteTests)
	report.Stats["actors"] = len(actors)
	for _, f := range findings {
		report.Stats["severity_"+f.Severity]++
		if f.Verified {
			report.Stats["verified"]++
		}
		if f.SideEffect.Verified {
			report.Stats["side_effects_verified"]++
		}
	}

	if opt.BaselinePath != "" {
		statErr := error(nil)
		_, statErr = os.Stat(opt.BaselinePath)
		if os.IsNotExist(statErr) {
			b := RegressionBaseline{Version: "", GeneratedAt: time.Now().UTC(), Observations: observations, Findings: findings, Graph: graph, Invariants: invariants}
			if err := writeJSON(opt.BaselinePath, b); err != nil {
				return Result{}, err
			}
		} else if statErr != nil {
			return Result{}, statErr
		} else {
			old, err := LoadBaseline(opt.BaselinePath)
			if err != nil {
				return Result{}, err
			}
			reg := CompareBaseline(old, observations)
			report.Findings = append(report.Findings, reg...)
			report.Stats["regressions"] = len(reg)
		}
	}
	if opt.JSONPath != "" {
		if err := writeJSON(opt.JSONPath, report); err != nil {
			return Result{}, err
		}
	}
	if opt.ReportPath != "" {
		if err := WriteHTML(opt.ReportPath, report); err != nil {
			return Result{}, err
		}
	}
	return Result{Report: report}, nil
}

func prepareRequests(items []BurpItem, cfg Config, opt Options) []preparedRequest {
	out := make([]preparedRequest, 0, len(items))
	for _, item := range items {
		req, ok := parseBurpRequest(item)
		if !ok || !mimeAllowed(item.Mimetype, cfg.FilterMimeTypes) {
			continue
		}
		refs := DiscoverObjects(req.URL, req.Body, opt.CustomPatterns)
		out = append(out, preparedRequest{Item: item, Req: req, Refs: refs})
	}
	return out
}

func collectBaseline(prepared []preparedRequest, cfg Config, actors []Actor, client Client, threads int, allowMutations bool) ([]Observation, map[string]accessRecord) {
	var mu sync.Mutex
	obs := make([]Observation, 0)
	access := map[string]accessRecord{}
	jobs := make(chan int)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for idx := range jobs {
			p := prepared[idx]
			if isMutating(p.Req.Method) && !allowMutations {
				continue
			}
			for _, actor := range actors {
				r := applyActor(withGlobalHeaders(p.Req, cfg.GlobalHeaders), actor)
				fp, body, _, err := client.Do(r)
				allowed := inferAllowed(fp, cfg.DenyStatuses)
				o := Observation{Actor: actor, URL: p.Req.URL, Endpoint: EndpointSignature(p.Req.Method, p.Req.URL, p.Refs), Method: p.Req.Method, Action: InferAction(p.Req.Method, p.Req.URL), Objects: p.Refs, Fingerprint: fp, Allowed: &allowed, Timestamp: time.Now().UTC(), RequestBody: p.Req.Body}
				if err != nil {
					o.Evidence = err.Error()
				}
				key := accessKey(actor.Name, o.Endpoint, p.Refs)
				mu.Lock()
				obs = append(obs, o)
				access[key] = accessRecord{Observation: o, Body: body}
				mu.Unlock()
			}
		}
	}
	if threads < 1 {
		threads = 1
	}
	if threads > len(prepared) && len(prepared) > 0 {
		threads = len(prepared)
	}
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker()
	}
	for i := range prepared {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	sort.Slice(obs, func(i, j int) bool { return obs[i].Timestamp.Before(obs[j].Timestamp) })
	return obs, access
}

func accessKey(actor, endpoint string, refs []ObjectRef) string {
	vals := make([]string, 0, len(refs))
	for _, r := range refs {
		vals = append(vals, r.Value)
	}
	sort.Strings(vals)
	return actor + "|" + endpoint + "|" + strings.Join(vals, ";")
}

func learnObjects(obs []Observation, access map[string]accessRecord) []learnedObject {
	out := []learnedObject{}
	seen := map[string]bool{}
	for _, o := range obs {
		if o.Allowed == nil || !*o.Allowed {
			continue
		}
		for _, r := range o.Objects {
			key := o.Actor.Name + "|" + o.Endpoint + "|" + r.Value
			if seen[key] {
				continue
			}
			seen[key] = true
			a := access[accessKey(o.Actor.Name, o.Endpoint, o.Objects)]
			out = append(out, learnedObject{Value: r.Value, Kind: CanonicalObjectKind(r.Kind), Actor: o.Actor, Endpoint: o.Endpoint, Observation: o, Body: a.Body})
		}
	}
	return out
}

func PlanTests(prepared []preparedRequest, obs []Observation, learned []learnedObject, actors []Actor, maxMutations int) []TestCase {
	if maxMutations < 1 {
		maxMutations = 1
	}
	observedByEndpoint := map[string][]learnedObject{}
	for _, l := range learned {
		observedByEndpoint[l.Endpoint] = append(observedByEndpoint[l.Endpoint], l)
	}
	out := []TestCase{}
	seen := map[string]bool{}
	for _, p := range prepared {
		for _, src := range actors {
			for _, target := range actors {
				if src.Name == target.Name {
					continue
				}
				for _, ref := range p.Refs {
					for _, candidate := range observedByEndpoint[EndpointSignature(p.Req.Method, p.Req.URL, p.Refs)] {
						if candidate.Actor.Name == src.Name || candidate.Kind != CanonicalObjectKind(ref.Kind) || candidate.Value == ref.Value {
							continue
						}
						key := "co|" + src.Name + "|" + target.Name + "|" + p.Req.URL + "|" + ref.Value + "|" + candidate.Value
						if seen[key] {
							continue
						}
						seen[key] = true
						kind := TestCrossObject
						if src.Tenant != "" && target.Tenant != "" && src.Tenant != target.Tenant {
							kind = TestCrossTenant
						}
						out = append(out, TestCase{ID: newID(), Kind: kind, SourceActor: src, TargetActor: target, Endpoint: EndpointSignature(p.Req.Method, p.Req.URL, p.Refs), Method: p.Req.Method, URL: p.Req.URL, SourceObject: ref.Value, TargetObject: ref.Value, ExpectedOwner: src.Name, ExpectedTenant: src.Tenant, ControlObject: candidate.Value, Reason: "cross-user object ownership proof via distinct control object"})
					}
					muts := GenerateMutations(ref, src)
					if len(muts) > maxMutations {
						muts = muts[:maxMutations]
					}
					for _, mv := range muts[1:] {
						key := "mut|" + src.Name + "|" + target.Name + "|" + p.Req.URL + "|" + ref.Value + "|" + mv
						if seen[key] {
							continue
						}
						seen[key] = true
						out = append(out, TestCase{ID: newID(), Kind: TestMutation, SourceActor: src, TargetActor: target, Endpoint: EndpointSignature(p.Req.Method, p.Req.URL, p.Refs), Method: p.Req.Method, URL: p.Req.URL, SourceObject: ref.Value, TargetObject: mv, Reason: "adaptive identifier mutation"})
					}
				}
			}
		}
	}
	return out
}

func executeTestCases(tests []TestCase, prepared []preparedRequest, access map[string]accessRecord, cfg Config, actors []Actor, client Client, opt Options) []Finding {
	_ = actors
	findings := []Finding{}
	for _, tc := range tests {
		p, ok := findPrepared(prepared, tc.Endpoint, tc.URL, tc.Method)
		if !ok {
			continue
		}
		owner, ok := findReferenceAccess(tc, access, tc.SourceActor, tc.Endpoint, tc.SourceObject)
		if !ok || owner.Observation.Allowed == nil || !*owner.Observation.Allowed {
			continue
		}
		control, controlOK := findReferenceAccess(tc, access, tc.TargetActor, tc.Endpoint, tc.ControlObject)
		sourceControl, sourceControlOK := findReferenceAccess(tc, access, tc.SourceActor, tc.Endpoint, tc.ControlObject)
		originalTarget, originalOK := findReferenceAccess(tc, access, tc.TargetActor, tc.Endpoint, tc.SourceObject)

		probeValue := tc.TargetObject
		mutated := replaceValue(p.Req, tc.SourceObject, probeValue)
		if tc.Kind == TestCrossObject || tc.Kind == TestCrossTenant {
			mutated = replaceValue(p.Req, tc.SourceObject, tc.SourceObject)
		}
		if isMutating(tc.Method) && !opt.AllowMutations {
			continue
		}

		var beforeFP ResponseFingerprint
		var beforeBody string
		haveBefore := false
		if opt.VerifySideEffects && opt.AllowMutations && opt.ExecuteTests && isMutating(tc.Method) {
			before := mutated
			before.Method = http.MethodGet
			var beforeErr error
			beforeFP, beforeBody, _, beforeErr = client.Do(applyActor(withGlobalHeaders(before, cfg.GlobalHeaders), tc.TargetActor))
			haveBefore = beforeErr == nil
		}

		fp, body, _, err := client.Do(applyActor(withGlobalHeaders(mutated, cfg.GlobalHeaders), tc.TargetActor))
		if err != nil {
			continue
		}
		allowed := inferAllowed(fp, cfg.DenyStatuses)
		sim := Similar(owner.Observation.Fingerprint, fp)
		containsOwner := responseContains(body, tc.SourceObject)
		controlAllowed := controlOK && control.Observation.Allowed != nil && *control.Observation.Allowed && tc.ControlObject != "" && tc.ControlObject != tc.SourceObject
		sourceDeniedControl := sourceControlOK && sourceControl.Observation.Allowed != nil && !*sourceControl.Observation.Allowed
		baselineDenied := originalOK && originalTarget.Observation.Allowed != nil && !*originalTarget.Observation.Allowed
		verified := false
		if tc.Kind == TestCrossObject || tc.Kind == TestCrossTenant {
			verified = controlAllowed && sourceDeniedControl && allowed && sim >= 0.70
		}
		if !allowed {
			continue
		}
		sev := "medium"
		typ := "Authorization mutation"
		conf := 60
		if tc.Kind == TestCrossObject {
			typ = "BOLA/IDOR"
			sev = "high"
			conf = 74
			if verified {
				typ = "Verified BOLA/IDOR"
				conf = 96
			}
		}
		if tc.Kind == TestCrossTenant {
			typ = "Cross-Tenant Authorization"
			sev = "critical"
			conf = 74
			if verified {
				typ = "Verified Cross-Tenant Authorization"
				conf = 97
			}
		}
		evidence := []string{fmt.Sprintf("owner actor=%s allowed object %s", owner.Observation.Actor.Name, tc.SourceObject), fmt.Sprintf("target status=%d", fp.Status), fmt.Sprintf("behavioral similarity=%.2f", sim)}
		if baselineDenied {
			evidence = append(evidence, "target actor was denied the owner's object in the pre-exploit control observation")
		}
		if controlAllowed {
			evidence = append(evidence, fmt.Sprintf("target actor's distinct control object %s was independently allowed", tc.ControlObject))
		}
		if sourceDeniedControl {
			evidence = append(evidence, fmt.Sprintf("source actor was denied the target actor's control object %s", tc.ControlObject))
		}
		if containsOwner {
			evidence = append(evidence, "response body echoed the owner's object reference")
		}
		if tc.SourceActor.Tenant != "" && tc.TargetActor.Tenant != "" && tc.SourceActor.Tenant != tc.TargetActor.Tenant {
			evidence = append(evidence, fmt.Sprintf("tenant boundary crossed: %s → %s", tc.SourceActor.Tenant, tc.TargetActor.Tenant))
		}
		chain := []string{fmt.Sprintf("%s (%s/%s) → owns/controls object %s → %s", tc.SourceActor.Name, tc.SourceActor.Role, tc.SourceActor.Tenant, tc.SourceObject, tc.Endpoint)}
		if tc.ControlObject != "" {
			chain = append(chain, fmt.Sprintf("%s (%s/%s) → independently allowed control object %s", tc.TargetActor.Name, tc.TargetActor.Role, tc.TargetActor.Tenant, tc.ControlObject))
		}
		chain = append(chain, fmt.Sprintf("%s → replays owner's object %s → %s", tc.TargetActor.Name, tc.SourceObject, map[bool]string{true: "authorization bypass VERIFIED", false: "suspicious access"}[verified]))
		f := Finding{ID: newID(), Type: typ, Severity: sev, Confidence: clampPercent(conf + similarityBonus(sim)), Verified: verified, Title: map[bool]string{true: "Verified unauthorized object access", false: "Potential authorization boundary weakness"}[verified], Summary: fmt.Sprintf("%s accessed object %s using an authorization context associated with %s.", tc.TargetActor.Name, tc.SourceObject, tc.SourceActor.Name), URL: tc.URL, Endpoint: tc.Endpoint, Method: tc.Method, SourceActor: tc.SourceActor, TargetActor: tc.TargetActor, SourceObject: tc.SourceObject, MutatedObject: probeValue, Evidence: evidence, ExploitChain: chain, Recommendations: []string{"Enforce object ownership checks at the service/data layer", "Enforce tenant isolation before reads and writes", "Keep this exact actor/object relationship in authorization regression coverage"}, TestCaseID: tc.ID}
		if opt.VerifySideEffects && opt.AllowMutations && opt.ExecuteTests && verified && isMutating(tc.Method) {
			if haveBefore {
				f.SideEffect = verifySideEffect(client, mutated, tc.TargetActor, cfg, beforeFP, beforeBody, fp)
			} else {
				f.SideEffect.Attempted = true
			}
			if f.SideEffect.Verified {
				f.Confidence = clampPercent(f.Confidence + 2)
			}
		}
		findings = append(findings, f)
	}
	return dedupeFindings(findings)
}

func verifySideEffect(client Client, r Request, actor Actor, cfg Config, beforeFP ResponseFingerprint, beforeBody string, mutFP ResponseFingerprint) SideEffectEvidence {
	ev := SideEffectEvidence{Attempted: true, BeforeStatus: beforeFP.Status, BeforeHash: beforeFP.BodyHash, VerificationURL: r.URL}
	after := r
	after.Method = http.MethodGet
	afterFP, afterBody, _, e := client.Do(applyActor(withGlobalHeaders(after, cfg.GlobalHeaders), actor))
	if e != nil {
		return ev
	}
	ev.AfterStatus = afterFP.Status
	ev.AfterHash = afterFP.BodyHash
	ev.StateChanged = mutFP.Status >= 200 && mutFP.Status < 400 && (beforeFP.BodyHash != afterFP.BodyHash || beforeFP.Status != afterFP.Status || strings.TrimSpace(beforeBody) != strings.TrimSpace(afterBody))
	ev.Verified = ev.StateChanged
	return ev
}

func isMutating(m string) bool {
	switch strings.ToUpper(m) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func findPrepared(prepared []preparedRequest, endpoint, urlStr, method string) (preparedRequest, bool) {
	for _, p := range prepared {
		if p.Req.Method == method && p.Req.URL == urlStr {
			return p, true
		}
	}
	for _, p := range prepared {
		if p.Req.Method == method && EndpointSignature(p.Req.Method, p.Req.URL, p.Refs) == endpoint {
			return p, true
		}
	}
	return preparedRequest{}, false
}

func findReferenceAccess(tc TestCase, access map[string]accessRecord, actor Actor, endpoint, object string) (accessRecord, bool) {
	keys := make([]string, 0, len(access))
	for k := range access {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := access[k]
		if !strings.HasPrefix(k, actor.Name+"|"+endpoint+"|") {
			continue
		}
		if object == "" {
			return v, true
		}
		for _, o := range v.Observation.Objects {
			if o.Value == object {
				return v, true
			}
		}
	}
	return accessRecord{}, false
}

func EndpointSignature(method, u string, refs []ObjectRef) string {
	_ = refs
	parsed, err := url.Parse(u)
	if err != nil {
		return method + " " + u
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "" {
			continue
		}
		if looksLikeObjectToken(p) {
			parts[i] = "{object}"
		}
	}
	return strings.ToUpper(method) + " " + strings.Join(parts, "/")
}

func looksLikeObjectToken(s string) bool {
	if _, err := url.PathUnescape(s); err == nil {
		s, _ = url.PathUnescape(s)
	}
	return uuidRe.MatchString(s) || numToken(s) || strings.Contains(strings.ToLower(s), "id-")
}

func numToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) <= 16
}

func similarityBonus(x float64) int {
	if x >= 0.9 {
		return 3
	}
	if x >= 0.8 {
		return 2
	}
	return 0
}

func clampPercent(x int) int {
	if x > 99 {
		return 99
	}
	if x < 0 {
		return 0
	}
	return x
}

func dedupeFindings(fs []Finding) []Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		k := f.Type + "|" + f.Endpoint + "|" + f.SourceActor.Name + "|" + f.TargetActor.Name + "|" + f.SourceObject + "|" + f.MutatedObject
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func parseBurpRequest(item BurpItem) (Request, bool) {
	raw, err := DecodeBurpRequest(item.Request)
	if err != nil {
		return Request{}, false
	}
	lines := strings.Split(raw, "\r\n")
	if len(lines) == 0 {
		return Request{}, false
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return Request{}, false
	}
	headers := map[string]string{}
	i := 1
	for i < len(lines) && lines[i] != "" {
		if p := strings.SplitN(lines[i], ":", 2); len(p) == 2 {
			headers[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
		}
		i++
	}
	body := ""
	if i+1 < len(lines) {
		body = strings.Join(lines[i+1:], "\r\n")
	}
	u := item.URL
	if parsed, e := url.Parse(u); e == nil && parsed.Scheme != "" {
		u = parsed.String()
	}
	return Request{URL: u, Method: parts[0], Body: body, Headers: headers}, true
}

func withGlobalHeaders(r Request, groups []map[string]string) Request {
	h := map[string]string{}
	for k, v := range r.Headers {
		h[k] = v
	}
	for _, g := range groups {
		for k, v := range g {
			h[k] = v
		}
	}
	r.Headers = h
	return r
}

func applyActor(r Request, a Actor) Request {
	h := map[string]string{}
	for k, v := range r.Headers {
		h[k] = v
	}
	for k, v := range a.Headers {
		h[k] = v
	}
	if h["User-Agent"] == "" {
		h["User-Agent"] = "AuthForge/"
	}
	r.Headers = h
	return r
}

func replaceValue(r Request, from, to string) Request {
	if from == "" || from == to {
		return r
	}
	if u, err := url.Parse(r.URL); err == nil {
		if u.Path != "" {
			parts := strings.Split(u.Path, "/")
			for i, part := range parts {
				if part == from {
					parts[i] = to
				}
			}
			u.Path = strings.Join(parts, "/")
			u.RawPath = ""
			r.URL = u.String()
		}
		values := u.Query()
		queryReplaced := false
		for key, vals := range values {
			if !isObjectParameter(key) {
				continue
			}
			changed := false
			for i, value := range vals {
				if value == from {
					vals[i] = to
					changed = true
				}
			}
			if changed {
				queryReplaced = true
				values[key] = vals
			}
		}
		if queryReplaced {
			u.RawQuery = values.Encode()
			r.URL = u.String()
		}
	}
	if replaced := replaceBodyObject(r.Body, from, to); replaced != r.Body {
		r.Body = replaced
	}
	return r
}

func isObjectParameter(key string) bool {
	l := strings.ToLower(key)
	for _, token := range []string{"id", "uid", "user", "account", "tenant", "order", "item", "invoice", "project", "object"} {
		if strings.Contains(l, token) {
			return true
		}
	}
	return false
}

func replaceBodyObject(body, from, to string) string {
	if strings.TrimSpace(body) == "" {
		return body
	}
	var v any
	if json.Unmarshal([]byte(body), &v) == nil {
		replaced, changed := replaceJSONValue(v, from, to)
		if changed {
			b, err := json.Marshal(replaced)
			if err == nil {
				return string(b)
			}
		}
		return body
	}
	values, err := url.ParseQuery(body)
	if err == nil && len(values) > 0 {
		changed := false
		for key, vals := range values {
			if !isObjectParameter(key) {
				continue
			}
			for i, value := range vals {
				if value == from {
					vals[i] = to
					changed = true
				}
			}
			values[key] = vals
		}
		if changed {
			return values.Encode()
		}
	}
	return body
}

func replaceJSONValue(v any, from, to string) (any, bool) {
	switch x := v.(type) {
	case map[string]any:
		changed := false
		for key, value := range x {
			if isObjectParameter(key) {
				switch candidate := value.(type) {
				case string:
					if candidate == from {
						x[key] = to
						changed = true
						continue
					}
				case float64:
					if parsedFrom, ok := parseNumeric(from); ok && candidate == parsedFrom {
						if parsedTo, ok := parseNumeric(to); ok {
							x[key] = parsedTo
							changed = true
							continue
						}
					}
				}
			}
			next, nextChanged := replaceJSONValue(value, from, to)
			if nextChanged {
				x[key] = next
				changed = true
			}
		}
		return x, changed
	case []any:
		changed := false
		for i, item := range x {
			next, nextChanged := replaceJSONValue(item, from, to)
			if nextChanged {
				x[i] = next
				changed = true
			}
		}
		return x, changed
	default:
		return v, false
	}
}

func parseNumeric(s string) (float64, bool) {
	if s == "" {
		return 0, false
	}
	n := 0.0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + float64(r-'0')
	}
	return n, true
}

func mimeAllowed(m string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	for _, x := range filters {
		if strings.EqualFold(strings.TrimSpace(m), strings.TrimSpace(x)) {
			return true
		}
	}
	return false
}

func inferAllowed(fp ResponseFingerprint, denies []int) bool {
	for _, d := range denies {
		if fp.Status == d {
			return false
		}
	}
	return fp.Status >= 200 && fp.Status < 400
}

func InferAction(method, u string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet:
		return "read"
	case http.MethodPost:
		return "create/action"
	case http.MethodPut, http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	}
	p := strings.ToLower(u)
	if strings.Contains(p, "admin") {
		return "admin"
	}
	return "request"
}

func writeJSON(path string, v any) error {
	d := filepath.Dir(path)
	if d != "." {
		if err := os.MkdirAll(d, 0755); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("finding-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
