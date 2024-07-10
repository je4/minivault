package config

import "embed"

//go:embed minivault.toml
var ConfigFS embed.FS
