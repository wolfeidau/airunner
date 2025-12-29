package assets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
	"github.com/rs/zerolog/log"
)

// Build runs esbuild with the configured settings and loads metadata
func (p *Pipeline) Build() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	entryPoints, err := filepath.Glob(p.config.EntryPointGlob)
	if err != nil {
		return err
	}

	if len(entryPoints) == 0 {
		return errors.New("no entry points found")
	}

	log.Info().Strs("entrypoints", entryPoints).Msg("Building assets")

	result := api.Build(api.BuildOptions{
		EntryPoints:       entryPoints,
		Bundle:            true,
		Splitting:         true,
		Write:             true,
		JSX:               api.JSXAutomatic,
		Outdir:            p.config.OutputDir,
		Format:            api.FormatESModule,
		MinifyWhitespace:  p.config.Minify,
		MinifyIdentifiers: p.config.Minify,
		MinifySyntax:      p.config.Minify,
		TreeShaking:       api.TreeShakingTrue,
		Sourcemap:         cond(p.config.SourceMap, api.SourceMapLinked, api.SourceMapNone),
		Metafile:          true,
	})

	if len(result.Errors) > 0 {
		for _, msg := range result.Errors {
			log.Error().Str("error", msg.Text).Msg("Build error")
		}
		return errors.New("esbuild failed with errors")
	}

	for _, file := range result.OutputFiles {
		log.Info().Str("file", file.Path).Msg("Built file")
	}

	// Write metafile
	if err := os.WriteFile(p.config.MetafilePath, []byte(result.Metafile), 0600); err != nil {
		return err
	}

	// Parse and cache metadata
	var metadata BuildMetadata
	if err := json.Unmarshal([]byte(result.Metafile), &metadata); err != nil {
		return err
	}

	p.metadata = &metadata
	return nil
}

// LoadScripts returns the ordered list of script and stylesheet paths needed for the given entrypoint
func (p *Pipeline) LoadScripts(entryPointPath string) ([]string, []string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.metadata == nil {
		return nil, nil, errors.New("assets not built yet, call Build() first")
	}

	scripts := []string{}
	styles := []string{}
	visited := make(map[string]bool)
	var jsOutputPath string

	// Find the output file for this entrypoint
	for outputPath, info := range p.metadata.Outputs {
		if info.EntryPoint == entryPointPath {
			jsOutputPath = outputPath
			// Separate JS and CSS
			if strings.HasSuffix(outputPath, ".css") {
				styles = append(styles, "/"+outputPath)
			} else {
				scripts = append(scripts, "/"+outputPath)
			}
			visited[outputPath] = true
			p.addDependencies(info, &scripts, &styles, visited)
			break
		}
	}

	if jsOutputPath == "" {
		return nil, nil, errors.New("entrypoint not found in metadata")
	}

	// Look for CSS bundle linked to this JS output
	for _, info := range p.metadata.Outputs {
		if info.EntryPoint == entryPointPath && info.CSSBundle != "" && !visited[info.CSSBundle] {
			styles = append(styles, "/"+info.CSSBundle)
			break
		}
	}

	return scripts, styles, nil
}

func (p *Pipeline) addDependencies(output OutputInfo, scripts, styles *[]string, visited map[string]bool) {
	for _, imp := range output.Imports {
		if !visited[imp.Path] {
			visited[imp.Path] = true
			if strings.HasSuffix(imp.Path, ".css") {
				*styles = append(*styles, "/"+imp.Path)
			} else {
				*scripts = append(*scripts, "/"+imp.Path)
			}

			if chunkInfo, exists := p.metadata.Outputs[imp.Path]; exists {
				p.addDependencies(chunkInfo, scripts, styles, visited)
			}
		}
	}
}

const templateName = "index.html"

// Handler returns an http.HandlerFunc that renders the embedded template with the given entrypoint, scripts, and styles
func (p *Pipeline) Handler(title, entryPointPath string, contextFn func(ctx context.Context) any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scripts, styles, err := p.LoadScripts(entryPointPath)
		if err != nil {
			log.Error().Err(err).Msg("Failed to load scripts")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if contextFn == nil {
			contextFn = func(ctx context.Context) any {
				return nil
			}
		}

		data := map[string]any{
			"Title":   title,
			"Scripts": scripts,
			"Styles":  styles,
			"Context": contextFn(r.Context()),
		}

		if err := p.tmpl.ExecuteTemplate(w, templateName, data); err != nil {
			log.Error().Err(err).Msg("Failed to render template")
		}
	}
}

func cond[T any](condition bool, trueVal, falseVal T) T {
	if condition {
		return trueVal
	}
	return falseVal
}
