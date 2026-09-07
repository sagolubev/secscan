// START_MODULE_CONTRACT
// PURPOSE: Validate offline rule bundles and expose immutable rule selection.
// SCOPE: Bound untrusted YAML, preserve engine IDs, and keep messages out of public metadata.
// DEPENDS: internal/discovery/inventory.go, internal/rules/store.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-reproducibility, internal/rules/pack_test.go#TestPackRejectsUnsafeGrammar
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Metadata - Portable declared provenance and verified rule counts.
// Rule - Sanitized original engine identity and declared language/severity.
// Rule.MatchesPath - Match a finding path to this rule's declared source languages.
// Pack - Immutable validated bundle snapshot.
// Pack.Metadata - Return independent metadata.
// Pack.Rules - Return independent rules matching a canonical language.
// Pack.MatchesPath - Match only recognized source paths and declared languages.
// Pack.Write - Materialize selected YAML in a private scanner directory without clobbering.
// Pack.WriteForPaths - Enforce per-rule language boundaries against the complete staged file set.
// boundedYAML.Write - Limit materialized scanner configuration bytes.
// END_MODULE_MAP

package rules

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/sagolubev/secscan/internal/discovery"
	"go.yaml.in/yaml/v3"
)

const (
	maxManifest  = 64 * 1024
	maxRuleFile  = 2 * 1024 * 1024
	maxBundle    = 16 * 1024 * 1024
	maxFiles     = 256
	maxRules     = 4096
	maxYAMLNodes = 100000
)

// Metadata describes declared provenance; License does not assert legal approval.
type Metadata struct {
	ID        string   `json:"id"`
	Source    string   `json:"source"`
	License   string   `json:"license"`
	Revision  string   `json:"revision,omitempty"`
	RuleCount int      `json:"ruleCount"`
	Languages []string `json:"languages"`
}

// Rule exposes original engine IDs without rule messages, snippets or metavariables.
type Rule struct {
	ID        string
	Languages []string
	Severity  string
}

// Pack is an immutable validated snapshot of an offline rule bundle.
type Pack struct {
	metadata Metadata
	rules    []Rule
	nodes    []*yaml.Node
}

type bundle struct {
	Version     int          `json:"version"`
	Source      string       `json:"source"`
	License     string       `json:"license"`
	Revision    string       `json:"revision,omitempty"`
	LicenseText string       `json:"licenseText"`
	Files       []bundleFile `json:"files"`
}

type bundleFile struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

// Metadata returns provenance and counts with independent language storage.
func (p Pack) Metadata() Metadata {
	m := p.metadata
	m.Languages = slices.Clone(m.Languages)
	return m
}

// Rules selects an exact canonical language; an empty language selects all rules.
func (p Pack) Rules(language string) []Rule {
	var result []Rule
	for _, rule := range p.rules {
		if language == "" || slices.Contains(rule.Languages, language) {
			rule.Languages = slices.Clone(rule.Languages)
			result = append(result, rule)
		}
	}
	return result
}

// MatchesPath classifies source paths without inferring generic or data languages.
func (p Pack) MatchesPath(filename string) bool {
	return (Rule{Languages: p.metadata.Languages}).MatchesPath(filename)
}

// MatchesPath checks this rule's languages using the same classification as pack routing.
func (r Rule) MatchesPath(filename string) bool {
	language := discovery.SourceLanguage(filename)
	if language == "shell" {
		language = "bash"
	}
	if language == "c-cpp" {
		switch strings.ToLower(filepath.Ext(filename)) {
		case ".c":
			language = "c"
		case ".h":
			return slices.Contains(r.Languages, "c") || slices.Contains(r.Languages, "cpp")
		default:
			language = "cpp"
		}
	}
	return language != "" && slices.Contains(r.Languages, language)
}

// Write creates one fixed YAML file from the snapshot in an existing private directory.
// Original IDs and DSL values survive; provenance and license text are not materialized.
func (p Pack) Write(directory, language string) error {
	return p.WriteForPaths(directory, language, nil)
}

// WriteForPaths materializes rules with exact exclusions for every staged file
// outside each rule's declared languages. Callers must supply the complete file set.
// Paths must be repository-relative and the engine must interpret leading-slash
// rule filters relative to its scan root. Legacy unanchored matchers are unsupported.
// Existing rule includes/excludes are retained; the cached snapshot is unchanged.
func (p Pack) WriteForPaths(directory, language string, paths []string) error {
	if len(paths) > maxYAMLNodes {
		return errors.New("too many rule-pack materialization paths")
	}
	paths = slices.Clone(paths)
	slices.Sort(paths)
	paths = slices.Compact(paths)
	patterns := make([]string, len(paths))
	pathBytes := 0
	for i, filename := range paths {
		pattern, err := exactPathPattern(filename)
		if err != nil {
			return err
		}
		pathBytes += len(pattern)
		if pathBytes > maxBundle {
			return errors.New("rule-pack materialization paths exceed size limit")
		}
		patterns[i] = pattern
	}
	addedNodes, addedBytes := 0, 0
	sequence := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for i, rule := range p.rules {
		if language != "" && !slices.Contains(rule.Languages, language) {
			continue
		}
		var exclusions []*yaml.Node
		for j, filename := range paths {
			if rule.MatchesPath(filename) {
				continue
			}
			addedNodes++
			addedBytes += len(patterns[j])
			if addedNodes > maxYAMLNodes || addedBytes > maxBundle {
				return errors.New("rule-pack language filters exceed materialization limit")
			}
			exclusions = append(exclusions, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: patterns[j]})
		}
		node := p.nodes[i]
		if len(exclusions) > 0 {
			var err error
			node, err = ruleWithExclusions(node, exclusions)
			if err != nil {
				return err
			}
		}
		sequence.Content = append(sequence.Content, node)
	}
	if len(sequence.Content) == 0 {
		return nil
	}
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rules"}, sequence}}
	var data boundedYAML
	encoder := yaml.NewEncoder(&data)
	if err := encoder.Encode(root); err != nil {
		return errors.New("encode rule-pack scanner input")
	}
	if err := encoder.Close(); err != nil {
		return errors.New("complete rule-pack scanner input")
	}
	return writeScannerInput(directory, data.buffer.Bytes())
}

type boundedYAML struct{ buffer bytes.Buffer }

// Write bounds YAML encoder output before it reaches the backing buffer.
func (w *boundedYAML) Write(data []byte) (int, error) {
	if len(data) > maxBundle-w.buffer.Len() {
		return 0, errors.New("rule-pack scanner input exceeds size limit")
	}
	return w.buffer.Write(data)
}

func exactPathPattern(filename string) (string, error) {
	if len(filename) > 4096 || !utf8.ValidString(filename) || !filepath.IsLocal(filename) || path.Clean(filename) != filename || filename == "." || strings.ContainsRune(filename, '\\') {
		return "", errors.New("invalid rule-pack materialization path")
	}
	var pattern strings.Builder
	pattern.WriteByte('/')
	for _, c := range filename {
		if c < 32 || c == 127 {
			return "", errors.New("invalid rule-pack materialization path")
		}
		if strings.ContainsRune("*?[]", c) {
			pattern.WriteByte('\\')
		}
		pattern.WriteRune(c)
	}
	return pattern.String(), nil
}

func ruleWithExclusions(node *yaml.Node, exclusions []*yaml.Node) (*yaml.Node, error) {
	clone := cloneRuleNode(node)
	var paths *yaml.Node
	for i := 0; i < len(clone.Content); i += 2 {
		if clone.Content[i].Value == "paths" {
			paths = clone.Content[i+1]
			break
		}
	}
	if paths == nil {
		paths = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		clone.Content = append(clone.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "paths"}, paths)
	}
	if paths.Kind != yaml.MappingNode {
		return nil, errors.New("rule-pack paths must be a mapping")
	}
	for i := 0; i < len(paths.Content); i += 2 {
		if paths.Content[i].Value != "exclude" {
			continue
		}
		exclude := paths.Content[i+1]
		if exclude.Kind != yaml.SequenceNode {
			return nil, errors.New("rule-pack path exclusions must be a sequence")
		}
		exclude.Content = append(exclude.Content, exclusions...)
		return clone, nil
	}
	paths.Content = append(paths.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "exclude"}, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: exclusions})
	return clone, nil
}

func cloneRuleNode(node *yaml.Node) *yaml.Node {
	clone := *node
	clone.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		clone.Content[i] = cloneRuleNode(child)
	}
	return &clone
}

func validateBundle(b bundle) (Pack, error) {
	if b.Version != 1 || !validSource(b.Source) || !printable(b.License, 256) || strings.TrimSpace(b.License) == "" || (b.Revision != "" && !lowerHex(b.Revision, 40) && !lowerHex(b.Revision, 64)) {
		return Pack{}, errors.New("invalid rule-pack provenance")
	}
	if len(b.LicenseText) > maxManifest || !utf8.ValidString(b.LicenseText) || strings.ContainsRune(b.LicenseText, 0) || strings.TrimSpace(b.LicenseText) == "" {
		return Pack{}, errors.New("invalid rule-pack license text")
	}
	if len(b.Files) == 0 || len(b.Files) > maxFiles {
		return Pack{}, errors.New("invalid rule-pack file count")
	}
	pack := Pack{metadata: Metadata{Source: b.Source, License: b.License, Revision: b.Revision}}
	ids := make(map[string]bool)
	languages := make(map[string]bool)
	previous := ""
	nodeCount := 0
	for _, file := range b.Files {
		if !validRelative(file.Name) || (path.Ext(file.Name) != ".yaml" && path.Ext(file.Name) != ".yml") || file.Name <= previous || len(file.Data) > maxRuleFile {
			return Pack{}, errors.New("invalid rule-pack file entry")
		}
		previous = file.Name
		nodes, err := parseRuleFile(file.Data, &nodeCount)
		if err != nil {
			return Pack{}, err
		}
		if len(pack.rules)+len(nodes) > maxRules {
			return Pack{}, errors.New("rule-pack rule count exceeds limit")
		}
		for _, node := range nodes {
			rule, err := parseRule(node)
			if err != nil {
				return Pack{}, err
			}
			if ids[rule.ID] {
				return Pack{}, errors.New("duplicate rule-pack rule ID")
			}
			ids[rule.ID] = true
			for _, language := range rule.Languages {
				languages[language] = true
			}
			pack.rules = append(pack.rules, rule)
			pack.nodes = append(pack.nodes, node)
		}
	}
	for language := range languages {
		pack.metadata.Languages = append(pack.metadata.Languages, language)
	}
	slices.Sort(pack.metadata.Languages)
	pack.metadata.RuleCount = len(pack.rules)
	return pack, nil
}

func parseRuleFile(data []byte, nodeCount *int) ([]*yaml.Node, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid rule-pack YAML")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document, extra yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("invalid rule-pack YAML")
	}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("rule-pack YAML must contain one document")
	}
	if err := validateYAML(&document, 0, nodeCount); err != nil {
		return nil, err
	}
	if len(document.Content) != 1 {
		return nil, errors.New("invalid rule-pack YAML root")
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode || len(root.Content) != 2 || root.Content[0].Value != "rules" {
		return nil, errors.New("rule-pack YAML root must contain only rules")
	}
	rules := root.Content[1]
	if rules.Kind != yaml.SequenceNode || len(rules.Content) == 0 {
		return nil, errors.New("rule-pack YAML requires a nonempty rules sequence")
	}
	return rules.Content, nil
}

func validateYAML(node *yaml.Node, depth int, count *int) error {
	*count++
	if depth > 64 || *count > maxYAMLNodes || node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return errors.New("unsafe or excessive rule-pack YAML structure")
	}
	switch node.Tag {
	case "", "!!map", "!!seq", "!!str", "!!int", "!!float", "!!bool", "!!null", "!!timestamp", "!!binary":
	default:
		return errors.New("unsupported rule-pack YAML tag")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]bool)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] || key.Value == "<<" {
				return errors.New("ambiguous rule-pack YAML mapping")
			}
			seen[key.Value] = true
			switch key.Value {
			case "pattern-where-python", "validator", "validators", "includes":
				return errors.New("unsafe rule-pack directive")
			case "include":
				// Semgrep paths.include is a local glob list, not a rule import.
				value := node.Content[i+1]
				if value.Kind != yaml.SequenceNode {
					return errors.New("unsafe rule-pack include")
				}
				for _, glob := range value.Content {
					if !stringNode(glob) || strings.Contains(glob.Value, ":") || strings.HasPrefix(glob.Value, "//") {
						return errors.New("remote rule-pack include is unsupported")
					}
				}
			}
		}
	}
	for _, child := range node.Content {
		if err := validateYAML(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func parseRule(node *yaml.Node) (Rule, error) {
	if node.Kind != yaml.MappingNode {
		return Rule{}, errors.New("rule-pack rule must be a mapping")
	}
	fields := make(map[string]*yaml.Node)
	for i := 0; i < len(node.Content); i += 2 {
		fields[node.Content[i].Value] = node.Content[i+1]
	}
	id, message, severity := fields["id"], fields["message"], fields["severity"]
	if !stringNode(id) || !validRuleID(id.Value) || !stringNode(message) || !stringNode(severity) {
		return Rule{}, errors.New("invalid rule-pack rule identity, message or severity")
	}
	if severity.Value != "ERROR" && severity.Value != "WARNING" && severity.Value != "INFO" {
		return Rule{}, errors.New("unsupported rule-pack severity")
	}
	languages := fields["languages"]
	if languages == nil || languages.Kind != yaml.SequenceNode || len(languages.Content) == 0 || len(languages.Content) > 18 {
		return Rule{}, errors.New("invalid rule-pack languages")
	}
	rule := Rule{ID: id.Value, Severity: strings.ToLower(severity.Value)}
	for _, language := range languages.Content {
		if !stringNode(language) || !validLanguage(language.Value) || slices.Contains(rule.Languages, language.Value) {
			return Rule{}, errors.New("unsupported or duplicate rule-pack language")
		}
		rule.Languages = append(rule.Languages, language.Value)
	}
	slices.Sort(rule.Languages)
	operator := false
	for _, name := range []string{"pattern", "patterns", "pattern-either", "pattern-regex", "match"} {
		if n := fields[name]; n != nil && ((n.Kind == yaml.ScalarNode && strings.TrimSpace(n.Value) != "") || len(n.Content) > 0) {
			operator = true
		}
	}
	if mode := fields["mode"]; stringNode(mode) && (mode.Value == "taint" || mode.Value == "extract") {
		operator = true
	}
	if !operator {
		return Rule{}, errors.New("rule-pack rule requires a pattern or supported mode")
	}
	return rule, nil
}

func stringNode(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Tag == "!!str"
}

func validLanguage(language string) bool {
	switch language {
	case "python", "javascript", "typescript", "go", "java", "ruby", "php", "c", "cpp", "csharp", "kotlin", "rust", "swift", "scala", "lua", "bash", "html", "css":
		return true
	}
	return false
}

func validRuleID(id string) bool {
	if len(id) == 0 || len(id) > 128 || strings.Contains(id, "secscan.") {
		return false
	}
	for i, c := range []byte(id) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || i > 0 && (c == '.' || c == '-')) {
			return false
		}
	}
	return true
}

func validSource(source string) bool {
	if source == "local" {
		return true
	}
	if !printable(source, 2048) {
		return false
	}
	u, err := url.Parse(source)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(source, "#") && u.Opaque == ""
}

func printable(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, c := range []byte(value) {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func validRelative(name string) bool {
	if len(name) == 0 || len(name) > 4096 || !utf8.ValidString(name) || !filepath.IsLocal(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\:") || name == "." {
		return false
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
