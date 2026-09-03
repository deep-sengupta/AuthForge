package engine

import (
	"encoding/json"
	"fmt"

	"html/template"
	"os"
	"sort"
)

const htmlTemplate = `<!doctype html><html><head><meta charset="utf-8"><title>AuthForge Report</title><style>body{font:14px system-ui;margin:32px;background:#0f1115;color:#eee}h1,h2{color:#fff}.card{background:#191d24;border:1px solid #303640;border-radius:12px;padding:16px;margin:12px 0}.sev-critical{border-left:5px solid #ff4d4d}.sev-high{border-left:5px solid #ff9f43}.sev-medium{border-left:5px solid #ffd166}.muted{color:#aab2bf}code{color:#8be9fd}.chain{font-family:monospace;white-space:pre-wrap}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}</style></head><body><h1>AuthForge  — Autonomous Authorization Attack Report</h1><p class="muted">Generated {{.GeneratedAt}} · {{.Stats.findings}} findings · {{.Stats.requests}} requests · {{.Stats.observations}} observations</p><div class="grid">{{range $k,$v:=.Stats}}<div class="card"><b>{{$k}}</b><div style="font-size:28px">{{$v}}</div></div>{{end}}</div><h2>Findings</h2>{{range .Findings}}<div class="card sev-{{.Severity}}"><b>{{.Severity | printf "%s"}} — {{.Title}}</b><p>{{.Summary}}</p><div><code>{{.Method}} {{.URL}}</code></div><p><b>{{.SourceActor.Name}}</b> → <b>{{.TargetActor.Name}}</b> · confidence {{.Confidence}}% · verified={{.Verified}}</p><div class="chain">{{range .ExploitChain}}{{.}}
{{end}}</div>{{range .Evidence}}<div class="muted">• {{.}}</div>{{end}}</div>{{else}}<div class="card">No findings.</div>{{end}}<h2>Authorization Graph</h2><div class="card">{{len .Graph.Nodes}} nodes · {{len .Graph.Edges}} edges</div></body></html>`

func WriteHTML(path string, r Report) error {
	if err := os.MkdirAll(dir(path), 0755); err != nil {
		return err
	}
	t, err := template.New("r").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, r)
}
func dir(p string) string {
	d := p
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			d = p[:i]
			break
		}
		if i == 0 {
			d = "."
		}
	}
	if d == "" {
		d = "."
	}
	return d
}
func Summarize(r Report) string {
	b, _ := json.MarshalIndent(r.Stats, "", "  ")
	return string(b)
}
func SortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool { return fs[i].Confidence > fs[j].Confidence })
}
func GraphDOT(g AuthorizationGraph) string {
	s := "digraph Authorization {\n"
	for _, n := range g.Nodes {
		s += fmt.Sprintf("\"%s\" [label=\"%s\"];\n", safe(n.ID), safe(n.Label))
	}
	for _, e := range g.Edges {
		allowed := ""
		if e.Allowed != nil {
			allowed = fmt.Sprintf(", allowed=%t", *e.Allowed)
		}
		s += fmt.Sprintf("\"%s\" -> \"%s\" [label=\"%s%s\"];\n", safe(e.From), safe(e.To), safe(e.Relation), safe(allowed))
	}
	return s + "}\n"
}
