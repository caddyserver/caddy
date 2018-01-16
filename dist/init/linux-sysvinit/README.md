SysVinit conf for Caddy
=======================

Usage
-----

* Download the appropriate Caddy binary in `/usr/local/bin/caddy` or use `curl https://getcaddy.com | bash`.
* Save the SysVinit config file in `/etc/init.d/caddy`.
* Ensure that the folder `/etc/caddy` exists and that the folder `/etc/ssl/caddy` is owned by `www-data`.
* Create a Caddyfile in `/etc/caddy/Caddyfile`
* Now you can use `service caddy start|stop|restart|reload|status` as `root`.

Init script manipulation
-----

The init script supports configuration via the following files:
* `/etc/default/caddy` ( Debian based https://www.debian.org/doc/manuals/debian-reference/ch03.en.html#_the_default_parameter_for_each_init_script )
* `/etc/sysconfig/caddy` ( CentOS based https://www.centos.org/docs/5/html/5.2/Deployment_Guide/s1-sysconfig-files.html )

The following variables can be changed:
* DAEMON: path to the caddy binary file (default: `/usr/local/bin/caddy`)
* DAEMONUSER: user used to run caddy (default: `www-data`)
* PIDFILE: path to the pidfile (default: `/var/run/$NAME.pid`)
* LOGFILE: path to the log file for caddy daemon (not for access logs) (default: `/var/log/$NAME.log`)
* CONFIGFILE: path to the caddy configuration file (default: `/etc/caddy/Caddyfile`)
* CADDYPATH: path for SSL certificates managed by caddy (default: `/etc/ssl/caddy`)
* ULIMIT: open files limit (default: `8192`)
