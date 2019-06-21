# Logging the caddy process's output:

Caddy's FreeBSD `rc.d` script uses `daemon` to run `caddy`; by default
it sends the process's standard output and error to syslog with the
`caddy` tag, the `local7` facility and the `notice` level.

The stock FreeBSD `/etc/syslog.conf` has a line near the top that
captures nearly anything logged at the `notice` level or higher and
sends it to `/var/log/messages`.  That line will send the caddy
process's output to `/var/log/messages`.

The simplest way to send `caddy` output to a separate file is:

- to log the messages at a lower level so that they slip past that
  early rule, e.g. add an `/etc/rc.conf` entry like

  ``` shell
  caddy_syslog_level="info"
  ```

- and then add a rule that catches them, e.g. by creating a
  `/usr/local/etc/syslog.d/caddy.conf` file that contains:

  ```
  # Capture all messages tagged with "caddy" and send them to /var/log/caddy.log
  !caddy
  *.*      /var/log/caddy.log
  ```

  Heads up, if you specify a file that does not already exist, you'll
  need to create it.

There are many other ways to do it, read the `syslogd.conf` man page
for additional information.
