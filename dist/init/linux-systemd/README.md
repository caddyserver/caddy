# systemd unit for caddy

Please do not hesitate to ask if you have any questions.

## Quickstart

The provided unit file assumes that you want to run caddy as `www-data` and group `www-data`,
both having UID and GID 33 here.
Adjust this to your liking according to the preferences of you Linux distribution!

```bash
groupadd -g 33 www-data
useradd \
  -g www-data --no-user-group \
  --home-dir /var/www --no-create-home \
  --shell /usr/sbin/nologin \
  --system --uid 33 www-data

mkdir /etc/caddy
chown -R root:www-data /etc/caddy
mkdir /etc/ssl/caddy
chown -R www-data:root /etc/ssl/caddy
chmod 0770 /etc/ssl/caddy
```

- Install the unit configuration file: `cp caddy.service /etc/systemd/system/`
- Reload the systemd daemon: `systemctl daemon-reload`
- Make sure to [configure](#configuration) the service unit before starting caddy.
- Start caddy: `systemctl start caddy.service`
- Enable the service (automatically start on boot): `systemctl enable caddy.service`
- A folder `.caddy` will be created inside the home directory of the user that runs caddy;
  you can change that by providing an environment variable `HOME`,
  i.e. `Environment=HOME=/var/lib/caddy` will result in `/var/lib/caddy/.caddy`.

## Configuration

- Do not edit the systemd unit file directly. Instead, use systemd's builtin tools:
    - `systemctl edit caddy.service` to make user-local modifications
    - `systemctl edit --full caddy.service` for system-wide ones
- In most cases it is enough to override the `ExecStart` directive.
    - systemd needs absolute paths, therefore make sure that the path to caddy is correct.
    - example:

```ini
[Service]
; an empty value clears the original (and preceding) settings
ExecStart=
ExecStart=/usr/bin/caddy -conf="/etc/caddy/myCaddy.conf" -agree -email="my@mail.address"
```

- To view the resulting configuration use `systemctl cat caddy`
- Double check permissions of your *document root* path.
  The user caddy runs as needs to have access to it. For example:

```bash
# caddy would run as        www-data:www-data
# serving, in this example: /var/www

sudo -u www-data -g www-data -s \
  ls -hlAS /var/www
```

## Tips

- Use `log stdout` and `errors stderr` in your Caddyfile to utilize `journalctl`.
- `journalctl` is systemd's log query tool.
- Let's say you want all the log entries since the last boot, beginning from the last entry:
  `journalctl --reverse --boot --unit caddy.service`
- To follow caddy's log output: `journalctl -fu caddy.service`
- Send a signal to a service unit's main PID, e.g. have caddy reload its config:
  `systemctl kill --signal=USR1 caddy.service`
- If you have more files that start with `caddy` – like a `caddy.timer`, `caddy.path`, or `caddy.socket` – then it is important to append `.service`.
  Although if `caddy.service` is all you have, then you can just use `caddy` without any extension, such as in: `systemctl status caddy`

- You can make your other certificates and private key files accessible to a user `www-data` by command `setfacl`, if you must:

```bash
setfacl -m user:www-data:r-- /etc/ssl/private/my.key
```
