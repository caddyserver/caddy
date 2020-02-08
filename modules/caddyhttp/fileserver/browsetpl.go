// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fileserver

const defaultBrowseTemplate = `<!DOCTYPE html>
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
	background-color: #ffffff;
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
	width: 5%;
}

th:last-child,
td:last-child {
	width: 5%;
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
	color: #999;
}

h1 a {
	color: #000;
	margin: 0 4px;
}

h1 a:hover {
	text-decoration: underline;
}

h1 a:first-child {
	margin: 0;
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
	white-space: nowrap;
	font-size: 14px;
}

td:nth-child(2) {
	width: 80%;
}

td:nth-child(3),
th:nth-child(3) {
	padding: 0 20px 0 20px;
}

th:nth-child(4),
td:nth-child(4) {
	text-align: right;
}

td:nth-child(2) svg {
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

	td:nth-child(2) {
		width: auto;
	}

	th:nth-child(3),
	td:nth-child(3) {
		padding-right: 5%;
		text-align: right;
	}

	h1 {
		color: #000;
	}

	h1 a {
		margin: 0;
	}

	#filter {
		max-width: 100px;
	}
}
</style>
	</head>
	<body onload='initFilter()'>
		<svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" height="0" width="0" style="position: absolute;">
			<defs>
				<!-- Folder -->
				<g id="folder" fill-rule="nonzero" fill="none">
					<path d="M285.22 37.55h-142.6L110.9 0H31.7C14.25 0 0 16.9 0 37.55v75.1h316.92V75.1c0-20.65-14.26-37.55-31.7-37.55z" fill="#FFA000"/>
					<path d="M285.22 36H31.7C14.25 36 0 50.28 0 67.74v158.7c0 17.47 14.26 31.75 31.7 31.75H285.2c17.44 0 31.7-14.3 31.7-31.75V67.75c0-17.47-14.26-31.75-31.7-31.75z" fill="#FFCA28"/>
				</g>
				<g id="folder-shortcut" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
					<g id="folder-shortcut-group" fill-rule="nonzero">
						<g id="folder-shortcut-shape">
							<path d="M285.224876,37.5486902 L142.612438,37.5486902 L110.920785,0 L31.6916529,0 C14.2612438,0 0,16.8969106 0,37.5486902 L0,112.646071 L316.916529,112.646071 L316.916529,75.0973805 C316.916529,54.4456008 302.655285,37.5486902 285.224876,37.5486902 Z" id="Shape" fill="#FFA000"></path>
							<path d="M285.224876,36 L31.6916529,36 C14.2612438,36 0,50.2838568 0,67.7419039 L0,226.451424 C0,243.909471 14.2612438,258.193328 31.6916529,258.193328 L285.224876,258.193328 C302.655285,258.193328 316.916529,243.909471 316.916529,226.451424 L316.916529,67.7419039 C316.916529,50.2838568 302.655285,36 285.224876,36 Z" id="Shape" fill="#FFCA28"></path>
						</g>
						<path d="M126.154134,250.559184 C126.850974,251.883673 127.300549,253.006122 127.772602,254.106122 C128.469442,255.206122 128.919016,256.104082 129.638335,257.002041 C130.559962,258.326531 131.728855,259 133.100057,259 C134.493737,259 135.415364,258.55102 136.112204,257.67551 C136.809044,257.002041 137.258619,255.902041 137.258619,254.577551 C137.258619,253.904082 137.258619,252.804082 137.033832,251.457143 C136.786566,249.908163 136.561779,249.032653 136.561779,248.583673 C136.089726,242.814286 135.864939,237.920408 135.864939,233.273469 C135.864939,225.057143 136.786566,217.514286 138.180246,210.846939 C139.798713,204.202041 141.889234,198.634694 144.429328,193.763265 C147.216689,188.869388 150.678411,184.873469 154.836973,181.326531 C158.995535,177.779592 163.626149,174.883673 168.481552,172.661224 C173.336954,170.438776 179.113983,168.665306 185.587852,167.340816 C192.061722,166.218367 198.760378,165.342857 205.481514,164.669388 C212.18017,164.220408 219.598146,163.995918 228.162535,163.995918 L246.055591,163.995918 L246.055591,195.514286 C246.055591,197.736735 246.752431,199.510204 248.370899,201.059184 C250.214153,202.608163 252.079886,203.506122 254.372715,203.506122 C256.463236,203.506122 258.531277,202.608163 260.172223,201.059184 L326.102289,137.797959 C327.720757,136.24898 328.642384,134.47551 328.642384,132.253061 C328.642384,130.030612 327.720757,128.257143 326.102289,126.708163 L260.172223,63.4469388 C258.553756,61.8979592 256.463236,61 254.395194,61 C252.079886,61 250.236632,61.8979592 248.393377,63.4469388 C246.77491,64.9959184 246.07807,66.7693878 246.07807,68.9918367 L246.07807,100.510204 L228.162535,100.510204 C166.863084,100.510204 129.166282,117.167347 115.274437,150.459184 C110.666301,161.54898 108.350993,175.310204 108.350993,191.742857 C108.350993,205.279592 113.903236,223.912245 124.760454,247.438776 C125.00772,248.112245 125.457294,249.010204 126.154134,250.559184 Z" id="Shape" fill="#FFFFFF" transform="translate(218.496689, 160.000000) scale(-1, 1) translate(-218.496689, -160.000000) "></path>
					</g>
				</g>

				<!-- File -->
				<g id="file" stroke="#000" stroke-width="25" fill="#FFF" fill-rule="evenodd" stroke-linecap="round" stroke-linejoin="round">
					<path d="M13 24.12v274.76c0 6.16 5.87 11.12 13.17 11.12H239c7.3 0 13.17-4.96 13.17-11.12V136.15S132.6 13 128.37 13H26.17C18.87 13 13 17.96 13 24.12z"/>
					<path d="M129.37 13L129 113.9c0 10.58 7.26 19.1 16.27 19.1H249L129.37 13z"/>
				</g>
				<g id="file-shortcut" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
					<g id="file-shortcut-group" transform="translate(13.000000, 13.000000)">
						<g id="file-shortcut-shape" stroke="#000000" stroke-width="25" fill="#FFFFFF" stroke-linecap="round" stroke-linejoin="round">
							<path d="M0,11.1214886 L0,285.878477 C0,292.039924 5.87498876,296.999983 13.1728373,296.999983 L225.997983,296.999983 C233.295974,296.999983 239.17082,292.039942 239.17082,285.878477 L239.17082,123.145388 C239.17082,123.145388 119.58541,2.84217094e-14 115.369423,2.84217094e-14 L13.1728576,2.84217094e-14 C5.87500907,-1.71479982e-05 0,4.96022995 0,11.1214886 Z" id="rect1171"></path>
							<path d="M116.37005,0 L116,100.904964 C116,111.483663 123.258008,120 132.273377,120 L236,120 L116.37005,0 L116.37005,0 Z" id="rect1794"></path>
						</g>
						<path d="M47.803141,294.093878 C48.4999811,295.177551 48.9495553,296.095918 49.4216083,296.995918 C50.1184484,297.895918 50.5680227,298.630612 51.2873415,299.365306 C52.2089688,300.44898 53.3778619,301 54.7490634,301 C56.1427436,301 57.0643709,300.632653 57.761211,299.916327 C58.4580511,299.365306 58.9076254,298.465306 58.9076254,297.381633 C58.9076254,296.830612 58.9076254,295.930612 58.6828382,294.828571 C58.4355724,293.561224 58.2107852,292.844898 58.2107852,292.477551 C57.7387323,287.757143 57.5139451,283.753061 57.5139451,279.95102 C57.5139451,273.228571 58.4355724,267.057143 59.8292526,261.602041 C61.44772,256.165306 63.5382403,251.610204 66.0783349,247.62449 C68.8656954,243.620408 72.3274172,240.35102 76.4859792,237.44898 C80.6445412,234.546939 85.2751561,232.177551 90.1305582,230.359184 C94.9859603,228.540816 100.76299,227.089796 107.236859,226.006122 C113.710728,225.087755 120.409385,224.371429 127.13052,223.820408 C133.829177,223.453061 141.247152,223.269388 149.811542,223.269388 L167.704598,223.269388 L167.704598,249.057143 C167.704598,250.87551 168.401438,252.326531 170.019905,253.593878 C171.86316,254.861224 173.728893,255.595918 176.021722,255.595918 C178.112242,255.595918 180.180284,254.861224 181.82123,253.593878 L247.751296,201.834694 C249.369763,200.567347 250.291391,199.116327 250.291391,197.297959 C250.291391,195.479592 249.369763,194.028571 247.751296,192.761224 L181.82123,141.002041 C180.202763,139.734694 178.112242,139 176.044201,139 C173.728893,139 171.885639,139.734694 170.042384,141.002041 C168.423917,142.269388 167.727077,143.720408 167.727077,145.538776 L167.727077,171.326531 L149.811542,171.326531 C88.5120908,171.326531 50.8152886,184.955102 36.9234437,212.193878 C32.3153075,221.267347 30,232.526531 30,245.971429 C30,257.046939 35.5522422,272.291837 46.4094607,291.540816 C46.6567266,292.091837 47.1063009,292.826531 47.803141,294.093878 Z" id="Shape-Copy" fill="#000000" fill-rule="nonzero" transform="translate(140.145695, 220.000000) scale(-1, 1) translate(-140.145695, -220.000000) "></path>
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
						<th></th>
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
						<th class="hideable"></th>
					</tr>
					</thead>
					<tbody>
					{{- if .CanGoUp}}
					<tr>
						<td></td>
						<td>
							<a href="..">
								<span class="goup">Go up</span>
							</a>
						</td>
						<td>&mdash;</td>
						<td class="hideable">&mdash;</td>
						<td class="hideable"></td>
					</tr>
					{{- end}}
					{{- range .Items}}
					<tr class="file">
						<td></td>
						<td>
							<a href="{{html .URL}}">
								{{- if .IsDir}}
								<svg width="1.5em" height="1em" version="1.1" viewBox="0 0 317 259"><use xlink:href="#folder{{if .IsSymlink}}-shortcut{{end}}"></use></svg>
								{{- else}}
								<svg width="1.5em" height="1em" version="1.1" viewBox="0 0 265 323"><use xlink:href="#file{{if .IsSymlink}}-shortcut{{end}}"></use></svg>
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
						<td class="hideable"></td>
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
			filterEl.focus();

			function initFilter() {
				if (!filterEl.value) {
					var filterParam = new URL(window.location.href).searchParams.get('filter');
					if (filterParam) {
						filterEl.value = filterParam;
					}
				}
				filter();
			}

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
				e.textContent = d.toLocaleString([], {day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit"});
			}
			var timeList = Array.prototype.slice.call(document.getElementsByTagName("time"));
			timeList.forEach(localizeDatetime);
		</script>
	</body>
</html>`
