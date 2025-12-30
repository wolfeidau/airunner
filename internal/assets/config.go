package assets

type Config struct {
	// Entry point glob pattern (e.g., "ui/pages/*.tsx")
	EntryPointGlob string
	// Output directory for built files
	OutputDir string
	// Path to metafile (relative to OutputDir)
	MetafilePath string
	// Whether to minify output
	Minify bool
	// Whether to enable source maps
	SourceMap bool
}

// DefaultConfig returns a sensible default configuration
func DefaultConfig() Config {
	return Config{
		EntryPointGlob: "ui/pages/*.tsx",
		OutputDir:      "public",
		MetafilePath:   "public/meta.json",
		Minify:         true,
		SourceMap:      true,
	}
}
