package engine

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func DiscoverActors(items []BurpItem) []Actor {
	type candidate struct {
		actor       Actor
		fingerprint string
	}
	byFP := map[string]candidate{}
	for _, item := range items {
		raw, err := DecodeBurpRequest(item.Request)
		if err != nil {
			continue
		}
		headers := parseRawHeaders(raw)
		auth := firstHeader(headers, "authorization")
		cookie := firstHeader(headers, "cookie")
		if auth == "" && cookie == "" {
			continue
		}
		fpInput := auth + "\n" + cookie
		sum := sha256.Sum256([]byte(fpInput))
		fp := fmt.Sprintf("%x", sum[:])
		if _, ok := byFP[fp]; ok {
			continue
		}
		a := actorFromHeaders(headers, fp)
		byFP[fp] = candidate{actor: a, fingerprint: fp}
	}
	out := make([]Actor, 0, len(byFP))
	for _, c := range byFP {
		out = append(out, c.actor)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func actorFromHeaders(h map[string]string, fp string) Actor {
	a := Actor{Name: "actor-" + fp[:10], Role: "unknown", User: "", Tenant: "", Headers: map[string]string{}}
	for k, v := range h {
		if strings.EqualFold(k, "authorization") || strings.EqualFold(k, "cookie") {
			a.Headers[k] = v
		}
	}
	if auth := firstHeader(h, "authorization"); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token := strings.TrimSpace(auth[7:])
		if claims, ok := jwtClaims(token); ok {
			a.User = firstClaim(claims, "sub", "user", "username", "email", "uid")
			a.Role = firstClaim(claims, "role", "roles", "scope")
			a.Tenant = firstClaim(claims, "tenant", "tenant_id", "tenantId", "organization", "org_id")
			if a.User != "" {
				a.Name = a.User
			} else if a.Name == "" {
				a.Name = "actor-" + fp[:10]
			}
		}
	}
	if a.User == "" {
		a.User = firstHeader(h, "x-user")
	}
	if a.Role == "" || a.Role == "unknown" {
		a.Role = firstHeader(h, "x-role")
	}
	if a.Tenant == "" {
		a.Tenant = firstHeader(h, "x-tenant-id")
	}
	if a.Role == "" {
		a.Role = "unknown"
	}
	if a.User != "" {
		a.Name = a.User
	}
	return a
}

func parseRawHeaders(raw string) map[string]string {
	lines := strings.Split(raw, "\r\n")
	h := map[string]string{}
	for i := 1; i < len(lines); i++ {
		if lines[i] == "" {
			break
		}
		p := strings.SplitN(lines[i], ":", 2)
		if len(p) == 2 {
			h[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
		}
	}
	return h
}
func firstHeader(h map[string]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}
func firstClaim(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch x := v.(type) {
			case string:
				if x != "" {
					return x
				}
			case []any:
				if len(x) > 0 {
					return fmt.Sprint(x[0])
				}
			}
		}
	}
	return ""
}
func jwtClaims(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil, false
	}
	return m, true
}

func EnrichActorsFromTraffic(actors []Actor, items []BurpItem) []Actor {
	discovered := DiscoverActors(items)
	if len(actors) == 0 {
		return discovered
	}

	out := make([]Actor, 0, len(actors)+len(discovered))
	for i := range actors {
		a := actors[i]
		for _, d := range discovered {
			if sameCredential(a.Headers, d.Headers) {
				if a.User == "" {
					a.User = d.User
				}
				if a.Role == "" || a.Role == "unknown" {
					a.Role = d.Role
				}
				if a.Tenant == "" {
					a.Tenant = d.Tenant
				}
				if a.Name == "" {
					a.Name = d.Name
				}
				break
			}
		}
		if a.Role == "" {
			a.Role = "unknown"
		}
		if !containsEquivalentActor(out, a) {
			out = append(out, a)
		}
	}

	for _, d := range discovered {
		if !containsEquivalentActor(out, d) {
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].User < out[j].User
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func actorIdentityKey(a Actor) string {

	if v := firstCredential(a.Headers, "authorization"); v != "" {
		return "authorization:" + v
	}
	if v := firstCredential(a.Headers, "cookie"); v != "" {
		return "cookie:" + v
	}
	if a.User != "" {
		return "user:" + a.User
	}
	if a.Name != "" {
		return "name:" + a.Name
	}
	return ""
}

func firstCredential(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(strings.TrimSpace(k), name) {
			return v
		}
	}
	return ""
}

func sameCredential(a, b map[string]string) bool {
	for _, key := range []string{"authorization", "cookie"} {
		av := firstCredential(a, key)
		bv := firstCredential(b, key)
		if av != "" && bv != "" && av == bv {
			return true
		}
	}
	return false
}

func containsEquivalentActor(actors []Actor, candidate Actor) bool {
	for _, existing := range actors {
		if sameCredential(existing.Headers, candidate.Headers) {
			return true
		}
		if actorIdentityKey(existing) != "" && actorIdentityKey(existing) == actorIdentityKey(candidate) {
			return true
		}
	}
	return false
}
