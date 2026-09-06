// Package cppcheck embeds the reproducible Cppcheck recipe and source notices.
package cppcheck

import "embed"

// Files contains project-owned preparation assets; upstream source is fetched privately.
//
//go:embed Dockerfile THIRD_PARTY_NOTICES.md GCC-COPYING.RUNTIME
var Files embed.FS
