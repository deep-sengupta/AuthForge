package engine

import "time"

type Actor struct {
	Name    string            `yaml:"name" json:"name"`
	Role    string            `yaml:"role" json:"role"`
	User    string            `yaml:"user" json:"user"`
	Tenant  string            `yaml:"tenant" json:"tenant"`
	Headers map[string]string `yaml:"headers" json:"-"`
}

type ObjectRef struct {
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	Source     string `json:"source"`
	Param      string `json:"param,omitempty"`
	Location   string `json:"location,omitempty"`
	Confidence int    `json:"confidence"`
}

type ResponseFingerprint struct {
	Status         int      `json:"status"`
	BodyBytes      int      `json:"body_bytes"`
	BodyHash       string   `json:"body_hash"`
	NormalizedHash string   `json:"normalized_hash"`
	JSONShapeHash  string   `json:"json_shape_hash,omitempty"`
	SemanticHash   string   `json:"semantic_hash,omitempty"`
	HeaderHash     string   `json:"header_hash,omitempty"`
	Headers        []string `json:"headers,omitempty"`
	Redirect       string   `json:"redirect,omitempty"`
	DurationMS     int64    `json:"duration_ms"`
	Error          string   `json:"error,omitempty"`
}

type Observation struct {
	Actor       Actor               `json:"actor"`
	URL         string              `json:"url"`
	Endpoint    string              `json:"endpoint"`
	Method      string              `json:"method"`
	Action      string              `json:"action"`
	Objects     []ObjectRef         `json:"objects,omitempty"`
	Fingerprint ResponseFingerprint `json:"fingerprint"`
	Allowed     *bool               `json:"allowed,omitempty"`
	Evidence    string              `json:"evidence,omitempty"`
	Timestamp   time.Time           `json:"timestamp"`
	RequestBody string              `json:"-"`
}

type TestKind string

const (
	TestBaseline    TestKind = "baseline"
	TestCrossObject TestKind = "cross-object"
	TestMutation    TestKind = "mutation"
	TestCrossTenant TestKind = "cross-tenant"
	TestSideEffect  TestKind = "side-effect"
)

type TestCase struct {
	ID             string   `json:"id"`
	Kind           TestKind `json:"kind"`
	SourceActor    Actor    `json:"source_actor"`
	TargetActor    Actor    `json:"target_actor"`
	Endpoint       string   `json:"endpoint"`
	Method         string   `json:"method"`
	URL            string   `json:"url"`
	SourceObject   string   `json:"source_object,omitempty"`
	TargetObject   string   `json:"target_object,omitempty"`
	ExpectedOwner  string   `json:"expected_owner,omitempty"`
	ExpectedTenant string   `json:"expected_tenant,omitempty"`
	ControlObject  string   `json:"control_object,omitempty"`
	Reason         string   `json:"reason,omitempty"`
}

type SideEffectEvidence struct {
	Attempted       bool   `json:"attempted"`
	Verified        bool   `json:"verified"`
	BeforeStatus    int    `json:"before_status,omitempty"`
	AfterStatus     int    `json:"after_status,omitempty"`
	BeforeHash      string `json:"before_hash,omitempty"`
	AfterHash       string `json:"after_hash,omitempty"`
	StateChanged    bool   `json:"state_changed"`
	VerificationURL string `json:"verification_url,omitempty"`
}

type AttackPath struct {
	ID         string   `json:"id"`
	FindingID  string   `json:"finding_id"`
	Steps      []string `json:"steps"`
	Verified   bool     `json:"verified"`
	Confidence int      `json:"confidence"`
}

type Finding struct {
	ID              string             `json:"id"`
	Type            string             `json:"type"`
	Severity        string             `json:"severity"`
	Confidence      int                `json:"confidence"`
	Verified        bool               `json:"verified"`
	Title           string             `json:"title"`
	Summary         string             `json:"summary"`
	URL             string             `json:"url"`
	Endpoint        string             `json:"endpoint,omitempty"`
	Method          string             `json:"method"`
	SourceActor     Actor              `json:"source_actor"`
	TargetActor     Actor              `json:"target_actor"`
	SourceObject    string             `json:"source_object,omitempty"`
	MutatedObject   string             `json:"mutated_object,omitempty"`
	Evidence        []string           `json:"evidence"`
	ExploitChain    []string           `json:"exploit_chain,omitempty"`
	Recommendations []string           `json:"recommendations,omitempty"`
	SideEffect      SideEffectEvidence `json:"side_effect,omitempty"`
	TestCaseID      string             `json:"test_case_id,omitempty"`
	AttackPathID    string             `json:"attack_path_id,omitempty"`
}

type GraphNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

type GraphEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
	Allowed  *bool  `json:"allowed,omitempty"`
}

type AuthorizationGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type AuthorizationInvariant struct {
	Key      string `json:"key"`
	Actor    string `json:"actor"`
	Role     string `json:"role"`
	User     string `json:"user"`
	Tenant   string `json:"tenant"`
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Action   string `json:"action"`
	Object   string `json:"object,omitempty"`
	Expected bool   `json:"expected"`
	Source   string `json:"source"`
}

type RegressionBaseline struct {
	Version      string                   `json:"version"`
	GeneratedAt  time.Time                `json:"generated_at"`
	Observations []Observation            `json:"observations"`
	Findings     []Finding                `json:"findings"`
	Graph        AuthorizationGraph       `json:"graph"`
	Invariants   []AuthorizationInvariant `json:"invariants"`
}

type Report struct {
	GeneratedAt time.Time                `json:"generated_at"`
	Version     string                   `json:"version"`
	Findings    []Finding                `json:"findings"`
	Graph       AuthorizationGraph       `json:"authorization_graph"`
	Stats       map[string]int           `json:"stats"`
	Invariants  []AuthorizationInvariant `json:"authorization_invariants,omitempty"`
	TestCases   []TestCase               `json:"generated_tests,omitempty"`
	AttackPaths []AttackPath             `json:"attack_paths,omitempty"`
}
