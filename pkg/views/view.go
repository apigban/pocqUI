package views

import (
	"bytes"
	"html/template"
	"io"
	"net/http"
	"path/filepath"
)

var (
	TemplateDir string = "pkg/views/"
	LayoutDir   string = "pkg/views/layouts/"
	TemplateExt string = ".gohtml"
)

type View struct {
	Template *template.Template
	Layout   string
}

func (v View) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.Render(w, nil)
}

// Render is used to render the view with predefined layout
func (v *View) Render(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "text/html")
	switch data.(type) {
	case Data:
		// do nothing
	default:
		data = Data{
			Yield: data,
		}
	}
	// Write data to buffer before writing to response writer
	// this avoids the scenario where during template execution,
	// an error occurs, and part of the template is written
	// directly to responsewriter

	var buf bytes.Buffer

	if err := v.Template.ExecuteTemplate(&buf, v.Layout, data); err != nil {
		http.Error(w, "Something went wrong. If the problem persists, please email us.", http.StatusInternalServerError)
		return
	}

	io.Copy(w, &buf)
}

// NewView function parses all templates and returns a View type
// Panics when a template cannot be used.
func NewView(layout string, files ...string) *View {
	addTemplatePath(files)
	addTemplateExt(files)

	files = append(files, layoutFiles()...)

	t, err := template.ParseFiles(files...)
	if err != nil { // Parse a view that is not present, will kill the app (panic)
		panic(err)
	}

	return &View{
		Template: t,
		Layout:   layout,
	}
}

// layoutFiles returns a slice of strings representing the layout files used by templates
func layoutFiles() []string {
	files, err := filepath.Glob(LayoutDir + "*" + TemplateExt)
	if err != nil {
		panic(err)
	}
	return files
}

// addTemplatePath takes in a slice of strings
// representing file paths for temaplates, prepends the
// TemplateDir to each string in the slice
//
// Eg. the input {"home"} yield {"views/home"}
func addTemplatePath(files []string) {
	for i, f := range files {
		files[i] = TemplateDir + f
	}
}

// addTemplateExt takes in a slice of strings
// representing file paths for temaplates, prepends the
// TemplateExt to each string in the slice
//
// Eg. the input {"home"} yield {"home.gohtml"}
func addTemplateExt(files []string) {
	for i, f := range files {
		files[i] = f + TemplateExt
	}
}
