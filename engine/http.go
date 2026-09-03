package engine

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	locationIDRe = regexp.MustCompile(`[0-9a-fA-F-]{8,}`)
	uuidBodyRe   = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	numBodyRe    = regexp.MustCompile(`\b[0-9]{1,16}\b`)
	emailBodyRe  = regexp.MustCompile(`(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`)
	idLikeRe     = regexp.MustCompile(`^[0-9a-f-]{8,}$`)
)

type Request struct {
	URL, Method, Body string
	Headers           map[string]string
}

type Client struct {
	Timeout     time.Duration
	Proxy       string
	InsecureTLS bool
}

type clientKey struct {
	timeout     time.Duration
	proxy       string
	insecureTLS bool
}

var httpClients sync.Map

func (c Client) Do(r Request) (ResponseFingerprint, string, map[string]string, error) {
	req, err := http.NewRequest(r.Method, r.URL, bytes.NewBufferString(r.Body))
	if err != nil {
		return ResponseFingerprint{}, "", nil, err
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	client := c.sharedClient()
	start := time.Now()
	resp, err := client.Do(req)
	dur := time.Since(start)
	if err != nil {
		return ResponseFingerprint{DurationMS: dur.Milliseconds(), Error: err.Error()}, "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	fp := Fingerprint(resp, int(dur.Milliseconds()), body)
	headers := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	return fp, string(body), headers, nil
}

func (c Client) sharedClient() *http.Client {
	key := clientKey{timeout: c.Timeout, proxy: c.Proxy, insecureTLS: c.InsecureTLS}
	if v, ok := httpClients.Load(key); ok {
		return v.(*http.Client)
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: c.InsecureTLS},
		IdleConnTimeout:   90 * time.Second,
		MaxIdleConns:      100,
		MaxIdleConnsPerHost: 20,
	}
	if c.Proxy != "" {
		if u, e := url.Parse(c.Proxy); e == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	client := &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	actual, _ := httpClients.LoadOrStore(key, client)
	return actual.(*http.Client)
}

func Fingerprint(resp *http.Response, dur int, body []byte) ResponseFingerprint {
	return FingerprintBytes(resp.StatusCode, resp.Header, redirectURL(resp), dur, body)
}

func FingerprintBytes(status int, h http.Header, redirect *url.URL, dur int, body []byte) ResponseFingerprint {
	raw := sha256.Sum256(body)
	norm := sha256.Sum256(normalizeBody(body))
	shape := jsonShapeHash(body)
	semantic := semanticHash(body)
	headerNames := make([]string, 0, len(h))
	pairs := make([]string, 0, len(h))
	for k, values := range h {
		lk := strings.ToLower(k)
		headerNames = append(headerNames, lk)
		v := ""
		if len(values) > 0 {
			v = values[0]
		}
		if lk == "content-type" || lk == "location" || strings.HasPrefix(lk, "x-") {
			pairs = append(pairs, lk+":"+normalizeHeaderValue(lk, v))
		}
	}
	sort.Strings(headerNames)
	sort.Strings(pairs)
	hh := sha256.Sum256([]byte(strings.Join(pairs, "\n")))
	fp := ResponseFingerprint{
		Status: status, BodyBytes: len(body), BodyHash: hex.EncodeToString(raw[:]),
		NormalizedHash: hex.EncodeToString(norm[:]), JSONShapeHash: shape,
		SemanticHash: semantic, HeaderHash: hex.EncodeToString(hh[:]), Headers: headerNames,
		DurationMS: int64(dur),
	}
	if redirect != nil {
		fp.Redirect = redirect.String()
	}
	return fp
}

func normalizeHeaderValue(k, v string) string {
	if strings.EqualFold(k, "location") {
		return locationIDRe.ReplaceAllString(v, "<ID>")
	}
	if strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "cookie") {
		return "<REDACTED>"
	}
	return v
}

func normalizeBody(b []byte) []byte {
	s := strings.TrimSpace(string(b))
	s = uuidBodyRe.ReplaceAllString(s, "<UUID>")
	s = numBodyRe.ReplaceAllString(s, "<NUM>")
	s = emailBodyRe.ReplaceAllString(s, "<EMAIL>")
	return []byte(s)
}

func semanticHash(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) == nil {
		n := semanticValue(v)
		h := sha256.Sum256([]byte(n))
		return hex.EncodeToString(h[:])
	}
	h := sha256.Sum256(normalizeBody(b))
	return hex.EncodeToString(h[:])
}

func semanticValue(v any) string {
	switch x := v.(type) {
	case map[string]any:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		parts := make([]string, 0, len(ks))
		for _, k := range ks {
			parts = append(parts, k+"="+semanticValue(x[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			parts = append(parts, semanticValue(item))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case string:
		return "string:" + classifyString(x)
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	default:
		return "other"
	}
}

func classifyString(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "admin"):
		return "admin-like"
	case strings.Contains(l, "error") || strings.Contains(l, "denied"):
		return "error-like"
	case idLikeRe.MatchString(l):
		return "id-like"
	case strings.Contains(l, "@") && strings.Contains(l, "."):
		return "email-like"
	default:
		return "value"
	}
}

func jsonShapeHash(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return ""
	}
	h := sha256.Sum256([]byte(shapeOf(v)))
	return hex.EncodeToString(h[:])
}

func shapeOf(v any) string {
	switch x := v.(type) {
	case map[string]any:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return fmt.Sprintf("obj{%s}", strings.Join(ks, ","))
	case []any:
		return "array[" + fmt.Sprintf("%d", len(x)) + "]"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	default:
		return "other"
	}
}

func Similar(a, b ResponseFingerprint) float64 {
	if a.Error != "" || b.Error != "" {
		return 0
	}
	score := 0.0
	if a.Status == b.Status {
		score += 0.18
	}
	if a.JSONShapeHash != "" && a.JSONShapeHash == b.JSONShapeHash {
		score += 0.22
	}
	if a.SemanticHash != "" && a.SemanticHash == b.SemanticHash {
		score += 0.18
	}
	if a.NormalizedHash == b.NormalizedHash {
		score += 0.20
	}
	if a.HeaderHash != "" && a.HeaderHash == b.HeaderHash {
		score += 0.07
	}
	if overlap(a.Headers, b.Headers) > 0.70 {
		score += 0.05
	}
	if a.Redirect == b.Redirect {
		score += 0.04
	}
	if timingSimilar(a.DurationMS, b.DurationMS) {
		score += 0.06
	}
	return score
}

func timingSimilar(a, b int64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 700
}

func overlap(a, b []string) float64 {
	ma := map[string]bool{}
	for _, x := range a {
		ma[x] = true
	}
	hit := 0
	for _, x := range b {
		if ma[x] {
			hit++
		}
	}
	if len(a)+len(b) == 0 {
		return 1
	}
	return 2 * float64(hit) / float64(len(a)+len(b))
}

func redirectURL(resp *http.Response) *url.URL {
	u, err := resp.Location()
	if err != nil {
		return nil
	}
	return u
}

func responseContains(body, value string) bool {
	if value == "" {
		return false
	}
	return strings.Contains(body, value)
}
