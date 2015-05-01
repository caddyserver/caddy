// Package git is the middleware that pull sites from git repo
//
// Caddyfile Syntax :
//	git repo path {
//		repo
//		path
//		branch
//		key
//		interval
//	}
//	repo 	- git repository
// 		compulsory. Both ssh (e.g. git@github.com:user/project.git)
// 		and https(e.g. https://github.com/user/project) are supported.
//		Can be specified in either config block or top level
//
// 	path 	- directory to pull into
//		optional. Defaults to site root.
//
// 	branch 	- git branch or tag
//		optional. Defaults to master
//
// 	key 	- path to private ssh key
//		optional. Required for private repositories. e.g. /home/user/.ssh/id_rsa
//
// 	interval- interval between git pulls in seconds
//		optional. Defaults to 3600 (1 Hour).
//
// Examples :
//
// public repo pulled into site root
//	git github.com/user/myproject
//
// public repo pulled into mysite
//	git https://github.com/user/myproject mysite
//
// private repo pulled into mysite with tag v1.0 and interval of 1 day
//	git {
//		repo 	git@github.com:user/myproject
//		branch 	v1.0
//		path	mysite
//		key 	/home/user/.ssh/id_rsa
//		interval 86400 # 1 day
//	}
//
// Caddyfile with private git repo and php support via fastcgi.
// path defaults to /var/www/html/myphpsite as specified in root config.
//
//	0.0.0.0:8080
//
//	git {
//		repo 	git@github.com:user/myphpsite
//		key 	/home/user/.ssh/id_rsa
//		interval 86400 # 1 day
//	}
//
//	fastcgi / 127.0.0.1:9000 php
//
//	root /var/www/html/myphpsite
//
// A pull is first attempted after initialization. Afterwards, a pull is attempted
// after request to server and if time taken since last successful pull is higher than interval.
//
// After the first successful pull (should be during initialization except an error occurs),
// subsequent pulls are done in background and do not impact request time.
//
// Note: private repositories are currently only supported and tested on Linux and OSX
package git
