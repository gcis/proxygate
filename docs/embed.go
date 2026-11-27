// Package docs embeds the static documentation site so the admin server can
// serve it at /docs/ (the same files are published to GitHub Pages).
package docs

import "embed"

// FS holds the documentation pages and their assets.
//
//go:embed index.html api.html security.html docs.css docs.js screenshots
var FS embed.FS
