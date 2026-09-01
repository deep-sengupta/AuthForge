package engine

import (
	"bufio"
	"fmt"

	"strconv"
	"strings"
	"time"
)

func parseConfigYAML(text string) (Config, error) {
	var c Config
	scanner := bufio.NewScanner(strings.NewReader(text))
	section := ""
	currentActor := -1
	currentMapList := -1
	lines := []struct {
		indent int
		s      string
	}{}
	for scanner.Scan() {
		raw := strings.TrimRight(scanner.Text(), "\r")
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		lines = append(lines, struct {
			indent int
			s      string
		}{indent, t})
	}
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(l.s, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(l.s, "- "))
			if section == "actors" {
				var a Actor
				if strings.Contains(item, ":") {
					k, v := splitKV(item)
					setActor(&a, k, v)
				}
				c.Actors = append(c.Actors, a)
				currentActor = len(c.Actors) - 1
				currentMapList = -1
				continue
			}
			if section == "headers" {
				k, v := splitKV(item)
				c.GlobalHeaders = append(c.GlobalHeaders, map[string]string{unquote(k): unquote(v)})
				currentMapList = len(c.GlobalHeaders) - 1
				continue
			}
			if section == "filterMimeTypes" {
				c.FilterMimeTypes = append(c.FilterMimeTypes, unquote(item))
				continue
			}
			if section == "objectPatterns" {
				c.ObjectPatterns = append(c.ObjectPatterns, unquote(item))
				continue
			}
			continue
		}
		k, v := splitKV(l.s)
		if k == "" {
			continue
		}
		if l.indent == 0 {
			section = k
			currentActor = -1
			currentMapList = -1
			switch k {
			case "source":
				c.SourceFileName = unquote(v)
			case "baselineFile":
				c.BaselineFile = unquote(v)
			case "reportFile":
				c.ReportFile = unquote(v)
			case "maxMutations":
				c.MaxMutations = atoi(v)
			case "timeout":
				c.Timeout = parseDuration(v)
			case "verifySideEffects":
				c.VerifySideEffects = abool(v)
			case "executeTests":
				c.ExecuteTests = abool(v)
			case "allowMutations":
				c.AllowMutations = abool(v)
			case "autoDiscoverActors":
				c.AutoDiscoverActors = abool(v)
			case "denyStatuses":
				c.DenyStatuses = parseIntList(v)
			case "actors", "headers", "filterMimeTypes", "objectPatterns":
			default:
				section = ""
			}
			continue
		}
		if section == "actors" && currentActor >= 0 {
			setActorField(&c.Actors[currentActor], k, v)
		}
		if section == "headers" && currentMapList >= 0 {
			c.GlobalHeaders[currentMapList][unquote(k)] = unquote(v)
		}
	}
	if scanner.Err() != nil {
		return c, scanner.Err()
	}
	if c.SourceFileName == "" {
		return c, fmt.Errorf("source is required")
	}
	if c.Timeout <= 0 {
		c.Timeout = 8 * time.Second
	}
	if c.MaxMutations <= 0 {
		c.MaxMutations = 30
	}
	if len(c.DenyStatuses) == 0 {
		c.DenyStatuses = []int{401, 403, 404}
	}
	if !c.AutoDiscoverActors && len(c.Actors) == 0 {
		c.AutoDiscoverActors = true
	}
	return c, nil
}
func splitKV(s string) (string, string) {
	p := strings.Index(s, ":")
	if p < 0 {
		return "", ""
	}
	return strings.TrimSpace(s[:p]), strings.TrimSpace(s[p+1:])
}
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		s = s[1 : len(s)-1]
	}
	return s
}
func atoi(s string) int   { n, _ := strconv.Atoi(unquote(s)); return n }
func abool(s string) bool { b, _ := strconv.ParseBool(unquote(s)); return b }
func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(unquote(s))
	if err == nil {
		return d
	}
	n := atoi(s)
	return time.Duration(n) * time.Second
}
func parseIntList(s string) []int {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	var out []int
	for _, p := range strings.Split(s, ",") {
		if x := strings.TrimSpace(p); x != "" {
			out = append(out, atoi(x))
		}
	}
	return out
}
func setActor(a *Actor, k, v string) { setActorField(a, k, v) }
func setActorField(a *Actor, k, v string) {
	k = unquote(k)
	v = unquote(v)
	switch k {
	case "name":
		a.Name = v
	case "role":
		a.Role = v
	case "user":
		a.User = v
	case "tenant":
		a.Tenant = v
	case "headers":
	default:
		if a.Headers == nil {
			a.Headers = map[string]string{}
		}
		a.Headers[k] = v
	}
}
