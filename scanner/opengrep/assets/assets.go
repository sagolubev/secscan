package assets

import "embed"

//go:embed Dockerfile THIRD_PARTY_NOTICES.md rules/*
var Files embed.FS
