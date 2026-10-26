// Package actmigrations embeds the ACT schema so it ships inside the binary.
package actmigrations

import "embed"

// FS holds the ACT migrations.
//
//go:embed *.sql
var FS embed.FS
