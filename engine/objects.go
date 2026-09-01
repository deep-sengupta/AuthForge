package engine

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	uuidRe    = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	jwtRe     = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	namedIDRe = regexp.MustCompile(`(?i)(id|uid|user[_-]?id|account[_-]?id|tenant[_-]?id|object[_-]?id|order[_-]?id|item[_-]?id|invoice[_-]?id|project[_-]?id)[=:/_-]([A-Za-z0-9_-]{1,80})`)
	numRe     = regexp.MustCompile(`\b[0-9]{1,12}\b`)
)

func DiscoverObjects(rawURL, body string, custom []string) []ObjectRef {
	refs := make([]ObjectRef, 0)
	seen := map[string]bool{}
	add := func(r ObjectRef) {
		key := r.Kind + "|" + r.Value + "|" + r.Location
		if r.Value == "" || seen[key] || len(refs) >= 50 {
			return
		}
		seen[key] = true
		refs = append(refs, r)
	}

	for _, v := range uuidRe.FindAllString(rawURL, -1) {
		add(ObjectRef{Kind: "uuid", Value: v, Source: "url", Location: "url-path", Confidence: 98})
	}
	for _, v := range uuidRe.FindAllString(body, -1) {
		add(ObjectRef{Kind: "uuid", Value: v, Source: "body", Location: "body", Confidence: 96})
	}
	for _, v := range jwtRe.FindAllString(body, -1) {
		add(ObjectRef{Kind: "jwt", Value: v, Source: "body", Location: "body", Confidence: 35})
	}
	for _, m := range namedIDRe.FindAllStringSubmatch(rawURL+"\n"+body, -1) {
		if len(m) != 3 {
			continue
		}
		kind := strings.ToLower(strings.TrimSuffix(strings.ReplaceAll(m[1], "_", ""), "id"))
		if kind == "" {
			kind = "identifier"
		}
		add(ObjectRef{Kind: "named-id:" + kind, Value: m[2], Source: "named-id", Param: m[1], Location: "mixed", Confidence: 92})
	}
	urlObjectSurface := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		urlObjectSurface = u.EscapedPath() + "?" + u.RawQuery
	}
	for _, v := range numRe.FindAllString(urlObjectSurface, -1) {
		if v != "0" && objectLikeNumeric(urlObjectSurface, v) {
			add(ObjectRef{Kind: "numeric-id", Value: v, Source: "url", Location: "url", Confidence: 82})
		}
	}
	for _, v := range numRe.FindAllString(body, -1) {
		if v != "0" && objectLikeNumeric(body, v) {
			add(ObjectRef{Kind: "numeric-id", Value: v, Source: "body", Location: "body", Confidence: 74})
		}
	}
	for _, p := range custom {
		if r, err := regexp.Compile(p); err == nil {
			for _, v := range r.FindAllString(rawURL+"\n"+body, -1) {
				add(ObjectRef{Kind: "custom", Value: v, Source: p, Location: "custom", Confidence: 94})
			}
		}
	}
	return refs
}

func objectLikeNumeric(s, value string) bool {
	idx := strings.Index(s, value)
	if idx < 0 {
		return false
	}
	left := strings.ToLower(s[max(0, idx-24):idx])
	return strings.Contains(left, "id") || strings.Contains(left, "user") || strings.Contains(left, "tenant") || strings.Contains(left, "order") || strings.Contains(left, "invoice") || strings.Contains(left, "item") || strings.Contains(left, "account") || strings.Contains(left, "/")
}

func GenerateMutations(ref ObjectRef, actor Actor) []string {
	v := ref.Value
	out := []string{v}
	switch {
	case ref.Kind == "numeric-id":
		out = append(out, nextNum(v, 1), nextNum(v, -1), "1", "2", "999999", "1000000")
	case ref.Kind == "uuid":
		out = append(out, "00000000-0000-4000-8000-000000000000", "11111111-1111-4111-8111-111111111111")
	case strings.HasPrefix(ref.Kind, "named-id"):
		out = append(out, "1", "2", "admin", "test", "me", actor.User)
	case ref.Kind == "custom":
		out = append(out, "1", "2", "test", "admin")
	}
	uniq := map[string]bool{}
	result := make([]string, 0, len(out))
	for _, x := range out {
		if x != "" && !uniq[x] {
			uniq[x] = true
			result = append(result, x)
		}
	}
	return result
}

func nextNum(v string, delta int) string {
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return "1"
	}
	n += int64(delta)
	if n < 1 {
		n = 1
	}
	return strconv.FormatInt(n, 10)
}

func CanonicalObjectKind(kind string) string {
	if strings.HasPrefix(kind, "named-id:") {
		return "named-id"
	}
	return kind
}

func allDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return s != ""
}
