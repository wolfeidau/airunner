package assets

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"maps"
	"sync"
)

type BuildMetadata struct {
	Outputs map[string]OutputInfo `json:"outputs"`
}

type OutputInfo struct {
	EntryPoint string       `json:"entryPoint"`
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
func New(config Config) *Pipeline {
	return &Pipeline{
		config: config,
	}
}

// NewWithTemplate creates a new asset pipeline and loads a single template
func NewWithTemplate(config Config, templatePath string) (*Pipeline, error) {
	return NewWithTemplateAndFuncs(config, templatePath, nil)
}

// NewWithTemplateAndFuncs creates a new asset pipeline and loads a single template with custom functions
func NewWithTemplateAndFuncs(config Config, templatePath string, customFuncs template.FuncMap) (*Pipeline, error) {
	p := &Pipeline{
		config: config,
	}

	funcs := template.FuncMap{
		"marshal": marshal,
		"safe": func(s string) template.HTML {
			return template.HTML(s) //nolint:gosec
		},
	}

	// Merge custom functions
	maps.Copy(funcs, customFuncs)

	tmpl, err := template.New(templatePath).Funcs(funcs).ParseFiles(templatePath)
	if err != nil {
		return nil, err
	}
	p.tmpl = tmpl
	return p, nil
}

// NewWithTemplateDir creates a new asset pipeline and loads all templates from a directory
func NewWithTemplateDir(config Config, templateDir string) (*Pipeline, error) {
	return NewWithTemplateDirAndFuncs(config, templateDir, nil)
}

// NewWithTemplateDirAndFuncs creates a new asset pipeline and loads all templates from a directory with custom functions
func NewWithTemplateDirAndFuncs(config Config, templateDir string, customFuncs template.FuncMap) (*Pipeline, error) {
	p := &Pipeline{
		config: config,
	}

	funcs := template.FuncMap{
		"marshal": marshal,
		"safe": func(s string) template.HTML {
			return template.HTML(s) //nolint:gosec
		},
	}

	// Merge custom functions
	maps.Copy(funcs, customFuncs)

	tmpl, err := template.New(templateDir).Funcs(funcs).ParseGlob(templateDir + "/*.html")
	if err != nil {
		return nil, err
	}
	p.tmpl = tmpl
	return p, nil
}

func marshal(value any) string {
	buf := new(bytes.Buffer)

	if err := json.NewEncoder(buf).Encode(value); err != nil {
		panic(errors.New("context can only be json serializable"))
	}

	return buf.String()
}
