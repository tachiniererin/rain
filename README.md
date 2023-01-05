# rain

Fork of the rain BitTorrent client to add support for routing all torrent and DHT traffic through wireguard in userspace.
It uses [wireguard-go](https://github.com/WireGuard/wireguard-go) to establish a connection to a WireGuard endpoint and route traffic over it and does not need any system VPN support and does not interact with it in any special ways either. This makes it possible to e.g. use the torrent client with a VPN provider while also running Tailscale.

This fork will be maintained on a best effort basis only.

See [rain project page](https://github.com/cenkalti/rain) for the original client.

## Usage

Clone the repo, run `go build` and specify a WireGuard config file as follows:

`./rain -wgconf nl4-wireguard.conf download -t "magnet:?xt=urn:btih:fef84077088ca87ffd8afd644d0ef957d96243c3&dn=archlinux-2023.01.01-x86_64.iso"`
