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
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimRight(scanner.Text(), "\r")
		t := strings.TrimSpace(stripComment(raw))
		if t == "" {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		lines = append(lines, struct {
			indent int
			s      string
		}{indent, t})
	}
	if err := scanner.Err(); err != nil {
		return c, err
	}
	_ = lineNo
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(l.s, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(l.s, "- "))
			switch section {
			case "actors":
				var a Actor
				if strings.Contains(item, ":") {
					k, v := splitKV(item)
					if err := setActor(&a, k, v); err != nil {
						return c, err
					}
				}
				c.Actors = append(c.Actors, a)
				currentActor = len(c.Actors) - 1
				currentMapList = -1
			case "headers":
				k, v := splitKV(item)
				if k == "" {
					return c, fmt.Errorf("invalid header entry %q", item)
				}
				c.GlobalHeaders = append(c.GlobalHeaders, map[string]string{unquote(k): unquote(v)})
				currentMapList = len(c.GlobalHeaders) - 1
			case "filterMimeTypes":
				c.FilterMimeTypes = append(c.FilterMimeTypes, unquote(item))
			case "objectPatterns":
				c.ObjectPatterns = append(c.ObjectPatterns, unquote(item))
			}
			continue
		}
		k, v := splitKV(l.s)
		if k == "" {
			return c, fmt.Errorf("invalid config entry %q", l.s)
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
				n, err := atoi(v)
				if err != nil {
					return c, fmt.Errorf("maxMutations: %w", err)
				}
				c.MaxMutations = n
			case "timeout":
				d, err := parseDuration(v)
				if err != nil {
					return c, fmt.Errorf("timeout: %w", err)
				}
				c.Timeout = d
			case "verifySideEffects":
				b, err := abool(v)
				if err != nil {
					return c, fmt.Errorf("verifySideEffects: %w", err)
				}
				c.VerifySideEffects = b
			case "executeTests":
				b, err := abool(v)
				if err != nil {
					return c, fmt.Errorf("executeTests: %w", err)
				}
				c.ExecuteTests = b
			case "allowMutations":
				b, err := abool(v)
				if err != nil {
					return c, fmt.Errorf("allowMutations: %w", err)
				}
				c.AllowMutations = b
			case "autoDiscoverActors":
				b, err := abool(v)
				if err != nil {
					return c, fmt.Errorf("autoDiscoverActors: %w", err)
				}
				c.AutoDiscoverActors = b
			case "denyStatuses":
				values, err := parseIntList(v)
				if err != nil {
					return c, fmt.Errorf("denyStatuses: %w", err)
				}
				c.DenyStatuses = values
			case "actors", "headers", "filterMimeTypes", "objectPatterns":
			default:
				section = ""
			}
			continue
		}
		if section == "actors" && currentActor >= 0 {
			if err := setActorField(&c.Actors[currentActor], k, v); err != nil {
				return c, err
			}
		}
		if section == "headers" && currentMapList >= 0 {
			c.GlobalHeaders[currentMapList][unquote(k)] = unquote(v)
		}
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

func stripComment(s string) string {
	var quote rune
	for i, r := range s {
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimRight(s[:i], " \t")
		}
	}
	return s
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

func atoi(s string) (int, error) { return strconv.Atoi(unquote(s)) }

func abool(s string) (bool, error) { return strconv.ParseBool(unquote(s)) }

func parseDuration(s string) (time.Duration, error) {
	value := unquote(s)
	if d, err := time.ParseDuration(value); err == nil {
		return d, nil
	}
	n, err := atoi(value)
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Second, nil
}

func parseIntList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("expected bracketed integer list")
	}
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"))
	if s == "" {
		return nil, nil
	}
	out := make([]int, 0)
	for _, p := range strings.Split(s, ",") {
		x, err := atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, nil
}

func setActor(a *Actor, k, v string) error { return setActorField(a, k, v) }

func setActorField(a *Actor, k, v string) error {
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
	return nil
}
