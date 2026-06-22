# mod_bw 0.95 (Apache 2)

A per-VirtualHost and per-directory bandwidth and connection limiter for
Apache 2.

- Author: Ivan Barrera A. (Bruce)
- License: Apache License 2.0 (see `LICENSE`)
- Status: legacy / stable

> Legacy line. This is the stable 0.x series, kept here for existing users. The
> latest fixes (Apache 2.4 support, 64-bit counters, Windows throttling) are
> being validated with synthetic and real-world testing; once that settles, this
> line will be finalized as 1.0. Active development has moved to the
> [`v2-wip`](https://github.com/IvnSoft/mod_bw/tree/v2-wip) branch, a
> from-scratch rewrite that is where new work now lands.

mod_bw limits the bandwidth a site or directory may use, and the number of
simultaneous connections, on a per-VirtualHost basis. It works with most MPMs
and keeps its counters in shared memory. It has run for years on Linux, the
BSDs, macOS, Solaris and Windows.

## Install

You need the Apache 2 development headers (the `apache2-devel` / `httpd-devel`
package, which provides the APR headers and the `apxs` tool) and shared-memory
support in your OS, which you almost certainly have.

    apxs -i -a -c mod_bw.c

If `apxs` is not on your path, use its full path (often `/usr/sbin/apxs`). On
success, restart Apache. Many distributions also ship mod_bw as a package.

## Directives

### BandWidthModule On|Off

Enables the module for the scope. Off by default: nothing is limited until it
is On.

### ForceBandWidthModule On|Off

By default the module only acts on filtered output. With Force On, every request
is processed. Without it, select the content to limit, for example:

    AddOutputFilterByType MOD_BW text/html text/plain

### `BandWidth <from> <bytes/s>`

Total speed available to an origin. `<from>` is a host, a partial domain, an IP,
a network (`192.168.0.0/24`), or `all`. `0` means no limit. Order matters: the
first matching entry wins. A `u:<regex>` form matches by User-Agent.

    BandWidth localhost 10240
    BandWidth 192.168.218.5 0
    BandWidth "u:wget" 102400

### `MinBandWidth <from> <bytes/s>`

Minimum speed each client keeps no matter how many are connected. `0` uses the
default (256 bytes/s). `-1` gives every client the full BandWidth value as its
cap.

    BandWidth    all 102400
    MinBandWidth all 50000

### `LargeFileLimit <type> <min KB> <bytes/s>`

Limit by file extension and minimum size. `<type>` is a file suffix or `*`.

    LargeFileLimit .avi 500 10240

### `BandWidthPacket <size>`

Packet size used when splitting, from 1024 to 131072 (default 8192). Larger
sizes suit high-speed links.

### `BandWidthError <code>`

HTTP code returned when MaxConnection is reached (default 503). Any code from
300 to 599.

    ErrorDocument 510 /errors/maxconexceeded.html
    BandWidthError 510

### `MaxConnection <from> <max>`

Maximum simultaneous connections from an origin; connections over the limit get
the BandWidthError code. Requires a BandWidth entry for the same origin (the
count shares that memory). A `u:<regex>` form matches by User-Agent.

    BandWidth     all 102400000
    MaxConnection all 20

### Status callback

Set a handler on any vhost (an admin or otherwise private one is a good choice)
to view live stats:

    <Location /modbw>
      SetHandler modbw-handler
    </Location>

Then visit `/modbw`, or `/modbw?csv` for CSV. Columns: id, name (vhost and
scope), lock, count (connected clients), bw (bytes/s in use), bytes (last sent),
hits.

## Examples

Limit everyone on a vhost to 10 KB/s:

    <VirtualHost *>
      BandWidthModule On
      ForceBandWidthModule On
      BandWidth all 10240
      MinBandWidth all -1
      ServerName www.example.com
    </VirtualHost>

LAN users to 1000 KB/s with a 50 KB/s floor, and files over 500 KB to 50 KB/s:

    <VirtualHost *>
      BandWidthModule On
      ForceBandWidthModule On
      BandWidth all 1024000
      MinBandWidth all 50000
      LargeFileLimit * 500 50000
      ServerName www.example.com
    </VirtualHost>

## Notes

- Order matters: earlier BandWidth entries take precedence.
- A `<Directory>` context does not inherit the vhost's mod_bw directives; set the
  limits you want inside each directory block.
- If you use mod_proxy or mod_php and see no limiting, load mod_bw before them in
  httpd.conf (LoadModule order).
- Limits can only divide the bandwidth you have; they never create more.
