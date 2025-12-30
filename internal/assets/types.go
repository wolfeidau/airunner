package assets

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"maps"
	"sync"

	"github.com/rs/zerolog/log"
)

//go:embed pages/*.html
var pages embed.FS

type BuildMetadata struct {
	Outputs map[string]OutputInfo `json:"outputs"`
}

type OutputInfo struct {
	EntryPoint string       `json:"entryPoint"`
	CSSBundle  string       `json:"cssBundle"`
	Imports    []ImportInfo `json:"imports"`
}

type ImportInfo struct {
	Path string `json:"path"`
}

// Pipeline manages the asset build process and script loading
type Pipeline struct {
	config   Config
	metadata *BuildMetadata
	tmpl     *template.Template
	mu       sync.RWMutex
}

// New creates a new asset pipeline with the given configuration
// It loads the embedded templates from the assets package
func New(config Config) (*Pipeline, error) {
	return NewWithCustomFuncs(config, nil)
}

// NewWithCustomFuncs creates a new asset pipeline with custom template functions
// It loads the embedded template from the assets package
func NewWithCustomFuncs(config Config, customFuncs template.FuncMap) (*Pipeline, error) {
	return newWithEmbedTemplate(config, customFuncs)
}

// newWithEmbedTemplate loads the embedded index.html template
func newWithEmbedTemplate(config Config, customFuncs template.FuncMap) (*Pipeline, error) {
	const templateFile = "pages/index.html"

	p := &Pipeline{
		config: config,
	}

	funcs := template.FuncMap{
		"marshal": marshal,
		"safe":    safe,
	}

	// Merge custom functions
	if customFuncs != nil {
		maps.Copy(funcs, customFuncs)
	}

	tmpl, err := template.New("index.html").Funcs(funcs).ParseFS(pages, templateFile)
	if err != nil {
		return nil, errors.New("failed to load embedded template: " + err.Error())
	}
	p.tmpl = tmpl
	return p, nil
}

func marshal(value any) string {
	buf := new(bytes.Buffer)

	if err := json.NewEncoder(buf).Encode(value); err != nil {
		// Only log in development, and only log the error type, not the data
		log.Debug().Err(err).Msg("Template marshal failed")
		return "{}"
	}

	return buf.String()
}

func safe(s string) template.HTML {
	return template.HTML(s) //nolint:gosec
}
