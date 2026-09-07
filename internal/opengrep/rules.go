// START_MODULE_CONTRACT
// PURPOSE: Describe the effective built-in and custom rule selection.
// SCOPE: Preserve built-in identity when no custom rule applies.
// DEPENDS: internal/rules/pack.go, internal/report/rules.go, internal/opengrep/image.go
// LINKS: cmd/secscan/rules_test.go#TestAcceptanceRulePacks
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// RuleEvidence - Bind applied rules to immutable pack identity and declared provenance.
// END_MODULE_MAP

package opengrep

import (
	"crypto/sha256"
	"fmt"

	"github.com/sagolubev/secscan/internal/report"
	"github.com/sagolubev/secscan/internal/rules"
)

// RuleEvidence returns the effective digest, count and optional custom provenance.
func RuleEvidence(language string, pack *rules.Pack) (string, int, *report.RulePack) {
	count := languageRuleCount(language)
	if language == "" {
		count = RuleCount
	}
	if pack == nil {
		return RulePackDigest, count, nil
	}
	customCount := len(pack.Rules(language))
	if customCount == 0 {
		return RulePackDigest, count, nil
	}
	meta := pack.Metadata()
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(RulePackDigest+"\x00"+meta.ID+"\x00"+language)))
	return digest, count + customCount, &report.RulePack{ID: meta.ID, Source: meta.Source, License: meta.License, Revision: meta.Revision, RuleCount: customCount}
}
