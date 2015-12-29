package setup

import (
	"fmt"
	"io/ioutil"
	"text/template"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/browse"
)

// Browse configures a new Browse middleware instance.
func Browse(c *Controller) (middleware.Middleware, error) {
	configs, err := browseParse(c)
	if err != nil {
		return nil, err
	}

	browse := browse.Browse{
		Root:          c.Root,
		Configs:       configs,
		IgnoreIndexes: false,
	}

	return func(next middleware.Handler) middleware.Handler {
		browse.Next = next
		return browse
	}, nil
}

func browseParse(c *Controller) ([]browse.Config, error) {
	var configs []browse.Config

	appendCfg := func(bc browse.Config) error {
		for _, c := range configs {
			if c.PathScope == bc.PathScope {
				return fmt.Errorf("duplicate browsing config for %s", c.PathScope)
			}
		}
		configs = append(configs, bc)
		return nil
	}

	for c.Next() {
		var bc browse.Config

		// First argument is directory to allow browsing; default is site root
		if c.NextArg() {
			bc.PathScope = c.Val()
		} else {
			bc.PathScope = "/"
		}

		// Second argument would be the template file to use
		var tplText string
		if c.NextArg() {
			tplBytes, err := ioutil.ReadFile(c.Val())
			if err != nil {
				return configs, err
			}
			tplText = string(tplBytes)
		} else {
			tplText = defaultTemplate
		}

		// Build the template
		tpl, err := template.New("listing").Parse(tplText)
		if err != nil {
			return configs, err
		}
		bc.Template = tpl

		// Save configuration
		err = appendCfg(bc)
		if err != nil {
			return configs, err
		}
	}

	return configs, nil
}

// The default template to use when serving up directory listings
const defaultTemplate = `<!DOCTYPE html>
<html>
	<head>
		<title>{{.Name}}</title>
		<meta charset="utf-8">
		<style>
			* {
				padding: 0;
				margin: 0;
			}

			body {
				text-rendering: optimizespeed;
				font-family: FreeSans, Arimo, "Droid Sans", Helvetica, Arial, sans-serif;
				font-size: 1em;
			}

			main {
				margin-top: 3em;
			}

			header,
			header h1 {
				font-size: 1em;
			}

			header {
				position: fixed;
				top: 0;width: 100%;
				background: #333333;
				line-height: 3em;
				color: #FFFFFF;
				text-align: center;
			}

			header a {
				text-decoration: none;
				color: #FFFFFF;
			}

			header a.up {
				display: inline-block;
				position: absolute;
				left: 0;
				top: 0;
				width: 1.5em;
				font-size: 2em;
				text-align: center;
			}

			header h1 {
				white-space: nowrap;
				font-weight: normal;
				padding: 0 1em;
				overflow-x: hidden;
				text-overflow: ellipsis;
			}

			header h1.up {
				padding-left: 3em;
			}

			table {
				table-layout: fixed;
				width: 100%;
				max-width: 64em;
				border: 0;
				border-collapse: collapse;
				margin: 0 auto;
			}

			th,
			td {
				padding: 0.5em 1em;
				vertical-align: middle;
				line-height: 1.5em;
				/* emoji are kind of odd heights */
			}

			th:first-child,
			td:first-child {
				overflow-wrap: break-word;
				word-break: break-word;
			}

			th:nth-child(2),
			td:nth-child(2) {
				width: 4em;
			}

			th:last-child,
			td:last-child {
				width: 11em;
			}

			th {
				text-align: left;
			}

			th a {
				color: #000000;
				text-decoration: none;
			}

			@media (max-width: 48em) {
				.hideable {
					display: none;
				}
			}
		</style>
	</head>
	<body>
		<header>
			{{if .CanGoUp}}
			<a href=".." class="up" title="Up one level">&#11025;</a>
			<h1 class="up name">{{.Path}}</h1>
			{{else}}
			<h1 class="name">{{.Path}}</h1>
			{{end}}
		</header>
		<main>
			<table>
				<tr>
					<th>
						{{if and (eq .Sort "name") (ne .Order "desc")}}
						<a href="?sort=name&order=desc">Name &#9650;</a>
						{{else if and (eq .Sort "name") (ne .Order "asc")}}
						<a href="?sort=name&order=asc">Name &#9660;</a>
						{{else}}
						<a href="?sort=name&order=asc">Name</a>
						{{end}}
					</th>
					<th>
						{{if and (eq .Sort "size") (ne .Order "desc")}}
						<a href="?sort=size&order=desc">Size &#9650;</a>
						{{else if and (eq .Sort "size") (ne .Order "asc")}}
						<a href="?sort=size&order=asc">Size &#9660;</a>
						{{else}}
						<a href="?sort=size&order=asc">Size</a> {{end}}
					</th>
					<th class="hideable">
						{{if and (eq .Sort "time") (ne .Order "desc")}}
						<a href="?sort=time&order=desc">Modified &#9650;</a>
						{{else if and (eq .Sort "time") (ne .Order "asc")}}
						<a href="?sort=time&order=asc">Modified &#9660;</a>
						{{else}}
						<a href="?sort=time&order=asc">Modified</a>
						{{end}}
					</th>
				</tr>
				{{range .Items}}
				<tr>
					<td>
						{{if .IsDir}}&#128194;{{else}}&#128196;{{end}}
						<a href="{{.URL}}" class="name">{{.Name}}</a>
					</td>
					<td>{{.HumanSize}}</td>
					<td class="hideable">{{.HumanModTime "01/02/2006 03:04:05 PM"}}</td>
				</tr>
				{{end}}
			</table>
		</main>
	</body>
</html>`
