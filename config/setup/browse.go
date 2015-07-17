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
		Root:    c.Root,
		Configs: configs,
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
* { padding: 0; margin: 0; }

body {
	padding: 1% 2%;
	font: 16px Arial;
}

header {
	font-size: 45px;
	padding: 25px;
}

header a {
	text-decoration: none;
	color: inherit;
}

header .up {
	display: inline-block;
	height: 50px;
	width: 50px;
	text-align: center;
	margin-right: 20px;
}

header a.up:hover {
	background: #000;
	color: #FFF;
}

h1 {
	font-size: 30px;
	display: inline;
}

table {
	border: 0;
	border-collapse: collapse;
	max-width: 750px;
	margin: 0 auto;
}

th,
td {
	padding: 4px 20px;
	vertical-align: middle;
	line-height: 1.5em; /* emoji are kind of odd heights */
}

th {
	text-align: left;
}

th a {
	color: #000;
	text-decoration: none;
}

@media (max-width: 700px) {
	.hideable {
		display: none;
	}

	body {
		padding: 0;
	}

	header,
	header h1 {
		font-size: 16px;
	}

	header {
		position: fixed;
		top: 0;
		width: 100%;
		background: #333;
		color: #FFF;
		padding: 15px;
		text-align: center;
	}

	header .up {
		height: auto;
		width: auto;
		display: none;
	}

	header a.up {
		display: inline-block;
		position: absolute;
		left: 0;
		top: 0;
		width: 40px;
		height: 48px;
		font-size: 35px;
	}

	header h1 {
		font-weight: normal;
	}

	main {
		margin-top: 70px;
	}
}
</style>
	</head>
	<body>
		<header>
			{{if .CanGoUp}}
			<a href=".." class="up" title="Up one level">&#11025;</a>
			{{else}}
			<div class="up">&nbsp;</div>
			{{end}}

			<h1>{{.Path}}</h1>
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
						<a href="?sort=size&order=asc">Size</a>
						{{end}}
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
						<a href="{{.URL}}">{{.Name}}</a>
					</td>
					<td>{{.HumanSize}}</td>
					<td class="hideable">{{.HumanModTime "01/02/2006 3:04:05 PM -0700"}}</td>
				</tr>
				{{end}}
			</table>
		</main>
	</body>
</html>`
