# systemd unit for caddy

Please do not hesitate to ask [me](mailto:klingt.net+caddy@gmail.com) if you've any questions.

## Quickstart

- install the unit configuration file: `cp caddy@.service /etc/systemd/system`
- reload the systemd daemon: `systemctl deamon-reload`
- make sure to [configure](#configuration) the service unit before starting caddy
- start caddy: `systemctl start caddy@someuser`
- enable the service (automatically start on boot): `systemctl enable caddy@someuser`
- the `.caddy` folder will be created inside the users home directory that runs caddy, i.e. `/home/someuser/.caddy` for `systemctl start caddy@someuser`

## Configuration

- do not edit the systemd unit directly, use systemd's builtin tools:
    - `systemctl edit caddy@` to make user local modifications to the service unit
    - `systemctl edit --full caddy@` to make system-wide modifications
- in most cases it's enough to adapt the `ExecStart` directive:
    - `systemctl edit caddy@`
    - systemd needs absolute paths, therefore make sure that the path to caddy is correct
    - example:

```ini
[Service]
; reset the original setting
ExecStart=
ExecStart=/usr/bin/caddy -conf="/etc/caddy/myCaddy.conf" -agree -email="my@mail.address"
```

- to view your configuration use `systemctl cat caddy@`
- double check the permissions of your web root path to make sure that caddy can access it as its run user and group

## Tips

- use `log stdout` and `errors stderr` in your Caddyfile to make use of `journalctl`
- `journalctl` is systemd's log query tool
- lets say you want all the log entries for caddy since the last boot beginning from the last entry: `journalctl --reverse --boot --unit caddy@someuser`
- maybe you want to follow caddys log output: `journalctl -fu caddy@someuser`
- to send a signal to a service units main PID, e.g. let caddy reload its config: `systemctl kill --signal=USR1 caddy@someuser`
