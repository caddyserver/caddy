package markdown

import (
	"io/ioutil"
	"text/template"
)

func setDefaultTemplate(filename string) *template.Template {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}

	return template.Must(GetDefaultTemplate().Parse(string(buf)))
}

func SetTemplate(t *template.Template, name, filename string) error {

	// Read template
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	// Update if exists
	if tt := t.Lookup(name); tt != nil {
		_, err = tt.Parse(string(buf))
		return err
	}

	// Allocate new name if not
	_, err = t.New(name).Parse(string(buf))
	return err
}

func GetDefaultTemplate() *template.Template {
	return template.Must(template.New("").Parse(defaultTemplate))
}

const (
	defaultTemplate = `<!DOCTYPE html>
<html>
	<head>
		<title>{{.Doc.title}}</title>
		<meta charset="utf-8">{{range .Styles}}
		<link rel="stylesheet" href="{{.}}">{{end}}{{range .Scripts}}
		<script src="{{.}}"></script>{{end}}
	</head>
	<body>
		{{.Doc.body}}
	</body>
</html>`
)
