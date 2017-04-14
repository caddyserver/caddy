package browse

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"text/template"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
)

func init() {
	caddy.RegisterPlugin("browse", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Browse middleware instance.
func setup(c *caddy.Controller) error {
	configs, err := browseParse(c)
	if err != nil {
		return err
	}

	b := Browse{
		Configs:       configs,
		IgnoreIndexes: false,
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		b.Next = next
		return b
	})

	return nil
}

func browseParse(c *caddy.Controller) ([]Config, error) {
	var configs []Config

	cfg := httpserver.GetConfig(c)

	appendCfg := func(bc Config) error {
		for _, c := range configs {
			if c.PathScope == bc.PathScope {
				return fmt.Errorf("duplicate browsing config for %s", c.PathScope)
			}
		}
		configs = append(configs, bc)
		return nil
	}

	for c.Next() {
		var bc Config

		// First argument is directory to allow browsing; default is site root
		if c.NextArg() {
			bc.PathScope = c.Val()
		} else {
			bc.PathScope = "/"
		}

		bc.Fs = staticfiles.FileServer{
			Root: http.Dir(cfg.Root),
			Hide: httpserver.GetConfig(c).HiddenFiles,
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
		<title>{{html .Name}}</title>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
* { padding: 0; margin: 0; }

body {
	font-family: sans-serif;
	text-rendering: optimizespeed;
}

a {
	color: #006ed3;
	text-decoration: none;
}

a:hover,
h1 a:hover {
	color: #319cff;
}

header,
#summary {
	padding-left: 5%;
	padding-right: 5%;
}

th:first-child,
td:first-child {
	padding-left: 5%;
}

th:last-child,
td:last-child {
	padding-right: 5%;
}

header {
	padding-top: 25px;
	padding-bottom: 15px;
	background-color: #f2f2f2;
}

h1 {
	font-size: 20px;
	font-weight: normal;
	white-space: nowrap;
	overflow-x: hidden;
	text-overflow: ellipsis;
}

h1 a {
	color: inherit;
}

h1 a:hover {
	text-decoration: underline;
}

main {
	display: block;
}

.meta {
	font-size: 12px;
	font-family: Verdana, sans-serif;
	border-bottom: 1px solid #9C9C9C;
	padding-top: 10px;
	padding-bottom: 10px;
}

.meta-item {
	margin-right: 1em;
}

#filter {
	padding: 4px;
	border: 1px solid #CCC;
}

table {
	width: 100%;
	border-collapse: collapse;
}

tr {
	border-bottom: 1px dashed #dadada;
}

tbody tr:hover {
	background-color: #ffffec;
}

th,
td {
	text-align: left;
	padding: 10px 0;
}

th {
	padding-top: 15px;
	padding-bottom: 15px;
	font-size: 16px;
	white-space: nowrap;
}

th a {
	color: black;
}

th svg {
	vertical-align: middle;
}

td {
	font-size: 14px;
}

td:first-child {
	width: 50%;
}

th:last-child,
td:last-child {
	text-align: right;
}

td:first-child svg {
	position: absolute;
}

td .name,
td .goup {
	margin-left: 1.75em;
	word-break: break-all;
	overflow-wrap: break-word;
	white-space: pre-wrap;
}

.icon {
	margin-right: 5px;
}

.icon.sort {
	display: inline-block;
	width: 1em;
	height: 1em;
	position: relative;
	top: .2em;
}

.icon.sort .top {
	position: absolute;
	left: 0;
	top: -1px;
}

.icon.sort .bottom {
	position: absolute;
	bottom: -1px;
	left: 0;
}

footer {
	padding: 40px 20px;
	font-size: 12px;
	text-align: center;
}

@media (max-width: 600px) {
	.hideable {
		display: none;
	}

	td:first-child {
		width: auto;
	}

	th:nth-child(2),
	td:nth-child(2) {
		padding-right: 5%;
		text-align: right;
	}
}
</style>
	</head>
	<body>
		<svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" height="0" width="0" style="position: absolute;">
			<defs>
				<!-- Folder -->
				<linearGradient id="f" y2="640" gradientUnits="userSpaceOnUse" x2="244.84" gradientTransform="matrix(.97319 0 0 1.0135 -.50695 -13.679)" y1="415.75" x1="244.84">
					<stop stop-color="#b3ddfd" offset="0"/>
					<stop stop-color="#69c" offset="1"/>
				</linearGradient>
				<linearGradient id="e" y2="571.06" gradientUnits="userSpaceOnUse" x2="238.03" gradientTransform="translate(0,2)" y1="346.05" x1="236.26">
					<stop stop-color="#ace" offset="0"/>
					<stop stop-color="#369" offset="1"/>
				</linearGradient>
				<g id="folder" transform="translate(-266.06 -193.36)">
					<g transform="matrix(.066019 0 0 .066019 264.2 170.93)">
						<g transform="matrix(1.4738 0 0 1.4738 -52.053 -166.93)">
							<path fill="#69c" d="m98.424 343.78c-11.08 0-20 8.92-20 20v48.5 33.719 105.06c0 11.08 8.92 20 20 20h279.22c11.08 0 20-8.92 20-20v-138.78c0-11.08-8.92-20-20-20h-117.12c-7.5478-1.1844-9.7958-6.8483-10.375-11.312v-5.625-11.562c0-11.08-8.92-20-20-20h-131.72z"/>
							<rect rx="12.885" ry="12.199" height="227.28" width="366.69" y="409.69" x="54.428" fill="#369"/>
							<path fill="url(#e)" d="m98.424 345.78c-11.08 0-20 8.92-20 20v48.5 33.719 105.06c0 11.08 8.92 20 20 20h279.22c11.08 0 20-8.92 20-20v-138.78c0-11.08-8.92-20-20-20h-117.12c-7.5478-1.1844-9.7958-6.8483-10.375-11.312v-5.625-11.562c0-11.08-8.92-20-20-20h-131.72z"/>
							<rect rx="12.885" ry="12.199" height="227.28" width="366.69" y="407.69" x="54.428" fill="url(#f)"/>
						</g>
					</g>
				</g>

				<!-- File -->
				<linearGradient id="a">
					<stop stop-color="#cbcbcb" offset="0"/>
					<stop stop-color="#f0f0f0" offset=".34923"/>
					<stop stop-color="#e2e2e2" offset="1"/>
				</linearGradient>
				<linearGradient id="d" y2="686.15" xlink:href="#a" gradientUnits="userSpaceOnUse" y1="207.83" gradientTransform="matrix(.28346 0 0 .31053 -608.52 485.11)" x2="380.1" x1="749.25"/>
				<linearGradient id="c" y2="287.74" xlink:href="#a" gradientUnits="userSpaceOnUse" y1="169.44" gradientTransform="matrix(.28342 0 0 .31057 -608.52 485.11)" x2="622.33" x1="741.64"/>
				<linearGradient id="b" y2="418.54" gradientUnits="userSpaceOnUse" y1="236.13" gradientTransform="matrix(.29343 0 0 .29999 -608.52 485.11)" x2="330.88" x1="687.96">
					<stop stop-color="#fff" offset="0"/>
					<stop stop-color="#fff" stop-opacity="0" offset="1"/>
				</linearGradient>
				<g id="file" transform="translate(-278.15 -216.59)">
					<g fill-rule="evenodd" transform="matrix(.19775 0 0 .19775 381.05 112.68)">
						<path d="m-520.17 525.5v36.739 36.739 36.739 36.739h33.528 33.528 33.528 33.528v-36.739-36.739-36.739l-33.528-36.739h-33.528-33.528-33.528z" stroke-opacity=".36478" stroke-width=".42649" fill="#fff"/>
						<g>
							<path d="m-520.11 525.68v36.739 36.739 36.739 36.739h33.528 33.528 33.528 33.528v-36.739-36.739-36.739l-33.528-36.739h-33.528-33.528-33.528z" stroke-opacity=".36478" stroke="#000" stroke-width=".42649" fill="url(#d)"/>
							<path d="m-386 562.42c-10.108-2.9925-23.206-2.5682-33.101-0.86253 1.7084-10.962 1.922-24.701-0.4271-35.877l33.528 36.739z" stroke-width=".95407pt" fill="url(#c)"/>
							<path d="m-519.13 537-0.60402 134.7h131.68l0.0755-33.296c-2.9446 1.1325-32.692-40.998-70.141-39.186-37.483 1.8137-27.785-56.777-61.006-62.214z" stroke-width="1pt" fill="url(#b)"/>
						</g>
					</g>
				</g>

				<!-- Up arrow -->
				<g id="up-arrow" transform="translate(-279.22 -208.12)">
					<path transform="matrix(.22413 0 0 .12089 335.67 164.35)" stroke-width="0" d="m-194.17 412.01h-28.827-28.827l14.414-24.965 14.414-24.965 14.414 24.965z"/>
				</g>

				<!-- Down arrow -->
				<g id="down-arrow" transform="translate(-279.22 -208.12)">
					<path transform="matrix(.22413 0 0 -.12089 335.67 257.93)" stroke-width="0" d="m-194.17 412.01h-28.827-28.827l14.414-24.965 14.414-24.965 14.414 24.965z"/>
				</g>
			</defs>
		</svg>

		<header>
			<h1>
				{{range $i, $crumb := .Breadcrumbs}}<a href="{{html $crumb.Link}}">{{html $crumb.Text}}</a>{{if ne $i 0}}/{{end}}{{end}}
			</h1>
		</header>
		<main>
			<div class="meta">
				<div id="summary">
					<span class="meta-item"><b>{{.NumDirs}}</b> director{{if eq 1 .NumDirs}}y{{else}}ies{{end}}</span>
					<span class="meta-item"><b>{{.NumFiles}}</b> file{{if ne 1 .NumFiles}}s{{end}}</span>
					{{- if ne 0 .ItemsLimitedTo}}
					<span class="meta-item">(of which only <b>{{.ItemsLimitedTo}}</b> are displayed)</span>
					{{- end}}
					<span class="meta-item"><input type="text" placeholder="filter" id="filter" onkeyup='filter()'></span>
				</div>
			</div>
			<div class="listing">
				<table aria-describedby="summary">
					<thead>
					<tr>
						<th>
							{{- if and (eq .Sort "namedirfirst") (ne .Order "desc")}}
							<a href="?sort=namedirfirst&order=desc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}" class="icon"><svg width="1em" height=".5em" version="1.1" viewBox="0 0 12.922194 6.0358899"><use xlink:href="#up-arrow"></use></svg></a>
							{{- else if and (eq .Sort "namedirfirst") (ne .Order "asc")}}
							<a href="?sort=namedirfirst&order=asc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}" class="icon"><svg width="1em" height=".5em" version="1.1" viewBox="0 0 12.922194 6.0358899"><use xlink:href="#down-arrow"></use></svg></a>
							{{- else}}
							<a href="?sort=namedirfirst&order=asc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}" class="icon sort"><svg class="top" width="1em" height=".5em" version="1.1" viewBox="0 0 12.922194 6.0358899"><use xlink:href="#up-arrow"></use></svg><svg class="bottom" width="1em" height=".5em" version="1.1" viewBox="0 0 12.922194 6.0358899"><use xlink:href="#down-arrow"></use></svg></a>
							{{- end}}
							
							{{- if and (eq .Sort "name") (ne .Order "desc")}}
							<a href="?sort=name&order=desc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}">Name <svg width="1em" height=".5em" version="1.1" viewBox="0 0 12.922194 6.0358899"><use xlink:href="#up-arrow"></use></svg></a>
							{{- else if and (eq .Sort "name") (ne .Order "asc")}}
							<a href="?sort=name&order=asc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}">Name <svg width="1em" height=".5em" version="1.1" viewBox="0 0 12.922194 6.0358899"><use xlink:href="#down-arrow"></use></svg></a>
							{{- else}}
							<a href="?sort=name&order=asc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}">Name</a>
							{{- end}}
						</th>
						<th>
							{{- if and (eq .Sort "size") (ne .Order "desc")}}
							<a href="?sort=size&order=desc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}">Size <svg width="1em" height=".5em" version="1.1" viewBox="0 0 12.922194 6.0358899"><use xlink:href="#up-arrow"></use></svg></a>
							{{- else if and (eq .Sort "size") (ne .Order "asc")}}
							<a href="?sort=size&order=asc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}">Size <svg width="1em" height=".5em" version="1.1" viewBox="0 0 12.922194 6.0358899"><use xlink:href="#down-arrow"></use></svg></a>
							{{- else}}
							<a href="?sort=size&order=asc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}">Size</a>
							{{- end}}
						</th>
						<th class="hideable">
							{{- if and (eq .Sort "time") (ne .Order "desc")}}
							<a href="?sort=time&order=desc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}">Modified <svg width="1em" height=".5em" version="1.1" viewBox="0 0 12.922194 6.0358899"><use xlink:href="#up-arrow"></use></svg></a>
							{{- else if and (eq .Sort "time") (ne .Order "asc")}}
							<a href="?sort=time&order=asc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}">Modified <svg width="1em" height=".5em" version="1.1" viewBox="0 0 12.922194 6.0358899"><use xlink:href="#down-arrow"></use></svg></a>
							{{- else}}
							<a href="?sort=time&order=asc{{if ne 0 .ItemsLimitedTo}}&limit={{.ItemsLimitedTo}}{{end}}">Modified</a>
							{{- end}}
						</th>
					</tr>
					</thead>
					<tbody>
					{{- if .CanGoUp}}
					<tr>
						<td>
							<a href="..">
								<span class="goup">Go up</span>
							</a>
						</td>
						<td>&mdash;</td>
						<td class="hideable">&mdash;</td>
					</tr>
					{{- end}}
					{{- range .Items}}
					<tr class="file">
						<td>
							<a href="{{html .URL}}">
								{{- if .IsDir}}
								<svg width="1.5em" height="1em" version="1.1" viewBox="0 0 35.678803 28.527945"><use xlink:href="#folder"></use></svg>
								{{- else}}
								<svg width="1.5em" height="1em" version="1.1" viewBox="0 0 26.604381 29.144726"><use xlink:href="#file"></use></svg>
								{{- end}}
								<span class="name">{{html .Name}}</span>
							</a>
						</td>
						{{- if .IsDir}}
						<td data-order="-1">&mdash;</td>
						{{- else}}
						<td data-order="{{.Size}}">{{.HumanSize}}</td>
						{{- end}}
						<td class="hideable"><time datetime="{{.HumanModTime "2006-01-02T15:04:05Z"}}">{{.HumanModTime "01/02/2006 03:04:05 PM -07:00"}}</time></td>
					</tr>
					{{- end}}
					</tbody>
				</table>
			</div>
		</main>
		<footer>
			Served with <a rel="noopener noreferrer" href="https://caddyserver.com">Caddy</a>
		</footer>
		<script>
			var filterEl = document.getElementById('filter');
			function filter() {
				var q = filterEl.value.trim().toLowerCase();
				var elems = document.querySelectorAll('tr.file');
				elems.forEach(function(el) {
					if (!q) {
						el.style.display = '';
						return;
					}
					var nameEl = el.querySelector('.name');
					var nameVal = nameEl.textContent.trim().toLowerCase();
					if (nameVal.indexOf(q) !== -1) {
						el.style.display = '';
					} else {
						el.style.display = 'none';
					}
				});
			}

			function localizeDatetime(e, index, ar) {
				if (e.textContent === undefined) {
					return;
				}
				var d = new Date(e.getAttribute('datetime'));
				if (isNaN(d)) {
					d = new Date(e.textContent);
					if (isNaN(d)) {
						return;
					}
				}
				e.textContent = d.toLocaleString();
			}
			var timeList = Array.prototype.slice.call(document.getElementsByTagName("time"));
			timeList.forEach(localizeDatetime);
		</script>
	</body>
</html>`
