SysVinit conf for Caddy
=======================

Usage
-----

* Download the appropriate Caddy binary in `/usr/local/bin/caddy` or use `curl https://getcaddy.com | bash`.
* Save the SysVinit config file in `/etc/init.d/caddy`.
* Ensure that the folder `/etc/caddy` exists and that the subfolder `ssl` is owned by `www-data`.
* Create a Caddyfile in `/etc/caddy/Caddyfile`
* Now you can use `service caddy start|stop|restart|reload|status` as `root`.
