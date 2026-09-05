package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"authforge/engine"
)

func main() {
	var configPath, proxy, jsonOut, htmlOut, baseline, dotOut string
	var threads int
	var timeout time.Duration
	var insecure bool
	var verbose bool
	var mimeList bool
	var patterns string
	var maxMutations int
	var execute, allowMutations, verifySideEffects bool

	flag.StringVar(&configPath, "config", "init.yaml", "Config YAML")
	flag.StringVar(&proxy, "proxy", "", "HTTP proxy, e.g. http://127.0.0.1:8080")
	flag.StringVar(&jsonOut, "json", "authforge-report.json", "Machine-readable report")
	flag.StringVar(&htmlOut, "html", "authforge-report.html", "Human-readable report")
	flag.StringVar(&baseline, "baseline", "authforge-baseline.json", "Authorization regression baseline")
	flag.StringVar(&dotOut, "graph", "authforge-graph.dot", "Authorization graph in Graphviz DOT format")
	flag.IntVar(&threads, "threads", 8, "Concurrent endpoint workers")
	flag.DurationVar(&timeout, "timeout", 8*time.Second, "HTTP timeout")
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS certificate verification (use only in authorized testing)")
	flag.BoolVar(&verbose, "verbose", false, "Verbose logging")
	flag.BoolVar(&mimeList, "listmime", false, "List Burp MIME types and exit")
	flag.StringVar(&patterns, "object-pattern", "", "Custom object-reference regex (repeatable with comma-separated patterns)")
	flag.IntVar(&maxMutations, "max-mutations", 30, "Maximum mutations per discovered object")
	flag.BoolVar(&execute, "execute", false, "Execute live authorization probes; default is plan/dry-run")
	flag.BoolVar(&allowMutations, "allow-mutations", false, "Allow POST/PUT/PATCH/DELETE probes")
	flag.BoolVar(&verifySideEffects, "verify-side-effects", false, "Verify mutating findings using before/after GETs")
	flag.Parse()

	fmt.Println("AuthForge — Authorization Intelligence Engine")
	cfg, err := engine.LoadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}
	items, err := engine.ReadBurpXML(cfg.SourceFileName)
	if err != nil {
		log.Fatal(err)
	}
	if mimeList {
		for _, mime := range engine.ListMimeTypes(items) {
			fmt.Println(mime)
		}
		return
	}
	var custom []string
	if strings.TrimSpace(patterns) != "" {
		custom = strings.Split(patterns, ",")
	}
	custom = append(custom, cfg.ObjectPatterns...)
	if verbose {
		log.Printf("Loaded %d Burp requests and %d configured actors\n", len(items), len(cfg.Actors))
	}
	if !execute && cfg.ExecuteTests {
		log.Printf("WARNING: live execution enabled by config: executeTests=true")
	}
	if !allowMutations && cfg.AllowMutations {
		log.Printf("WARNING: mutating probes enabled by config: allowMutations=true")
	}
	if !verifySideEffects && cfg.VerifySideEffects {
		log.Printf("WARNING: side-effect verification enabled by config: verifySideEffects=true")
	}
	result, err := engine.Run(items, cfg, engine.Options{Proxy: proxy, Threads: threads, Timeout: timeout, InsecureTLS: insecure, VerifySideEffects: verifySideEffects || cfg.VerifySideEffects, BaselinePath: baseline, ReportPath: htmlOut, JSONPath: jsonOut, CustomPatterns: custom, MaxMutations: maxMutations, ExecuteTests: execute || cfg.ExecuteTests, AllowMutations: allowMutations || cfg.AllowMutations})
	if err != nil {
		log.Fatal(err)
	}
	if err := writeFile(dotOut, []byte(engine.GraphDOT(result.Report.Graph))); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Completed: %d findings (%d verified).\n", len(result.Report.Findings), result.Report.Stats["verified"])
	fmt.Printf("JSON: %s\nHTML: %s\nGraph: %s\nBaseline: %s\n", jsonOut, htmlOut, dotOut, baseline)
	if len(result.Report.Findings) > 0 {
		os.Exit(2)
	}
}
func writeFile(p string, b []byte) error { return os.WriteFile(p, b, 0600) }
