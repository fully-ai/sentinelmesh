package api

import "embed"

// WebAssets embeds the zero-dependency SentinelMesh SOC web dashboard.
//
//go:embed web
var WebAssets embed.FS
