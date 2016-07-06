Upstart conf for Caddy
=====================

Usage
-----

Usage in this blogpost: [Running Caddy Server as a service with Upstart](https://denbeke.be/blog/servers/running-caddy-server-as-a-service/).
Short recap:

* Download Caddy in `/usr/local/bin/caddy` and execute `sudo setcap cap_net_bind_service=+ep /usr/local/bin/caddy`.
* Save the upstart config file in `/etc/init/caddy.conf`.
* Ensure that the folder `/etc/caddy` exists and that the subfolder .caddy is owned by `www-data`.
* Create a Caddyfile in `/etc/caddy/Caddyfile`.
* Now you can use `sudo service caddy start|stop|restart`.
