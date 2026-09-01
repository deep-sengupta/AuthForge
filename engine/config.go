package engine

import (
	"fmt"

	"os"
	"time"
)

type Config struct {
	SourceFileName     string              `yaml:"source" json:"source"`
	FilterMimeTypes    []string            `yaml:"filterMimeTypes" json:"filterMimeTypes"`
	GlobalHeaders      []map[string]string `yaml:"headers" json:"headers"`
	Actors             []Actor             `yaml:"actors" json:"actors"`
	SeedRequests       int                 `yaml:"seedRequests" json:"seedRequests"`
	ObjectPatterns     []string            `yaml:"objectPatterns" json:"objectPatterns"`
	DenyStatuses       []int               `yaml:"denyStatuses" json:"denyStatuses"`
	BaselineFile       string              `yaml:"baselineFile" json:"baselineFile"`
	ReportFile         string              `yaml:"reportFile" json:"reportFile"`
	MaxMutations       int                 `yaml:"maxMutations" json:"maxMutations"`
	Timeout            time.Duration       `yaml:"timeout" json:"timeout"`
	VerifySideEffects  bool                `yaml:"verifySideEffects" json:"verifySideEffects"`
	ExecuteTests       bool                `yaml:"executeTests" json:"executeTests"`
	AllowMutations     bool                `yaml:"allowMutations" json:"allowMutations"`
	AutoDiscoverActors bool                `yaml:"autoDiscoverActors" json:"autoDiscoverActors"`
}

func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	c, err := parseConfigYAML(string(b))
	if err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if c.MaxMutations <= 0 {
		c.MaxMutations = 30
	}
	if c.Timeout <= 0 {
		c.Timeout = 8 * time.Second
	}
	if len(c.DenyStatuses) == 0 {
		c.DenyStatuses = []int{401, 403, 404}
	}
	return c, nil
}
