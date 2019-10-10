# any module that provisions resources
proxyConfig = {
	'load_balance_type': 'round_robin',
	'upstreams': [
		{
			'host': 'http://localhost:8080',
			'circuit_breaker': {
				'type': 'status_ratio',
				'threshold': 0.5
			}
		},
		{
			'host': 'http://localhost:8081'
		}
	]
}

sfConfig = {
	'root': '/Users/dev/Desktop',
	'browse': {},
}

proxy = loadResponder('reverse_proxy', proxyConfig)
static_files = loadResponder('file_server', sfConfig)

def setup(r):
	# create some middlewares specific to this request
	mid = []

	if r.query.get('log') == 'true':
		logMid = loadMiddleware('log', {'file': 'access.log'})
		mid.append(logMid)

	execute(mid)

def serveHTTP(w, r):
	if r.url.find('static') > 0:
		return static_files

	return proxy
