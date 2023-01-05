package netwrap

import (
	"context"
	"net"
)

// Network types and wrappers to change the network stack used for torrent and dht connections

type ListenTCP func(network string, laddr *net.TCPAddr) (net.Listener, error)
type ListenUDP func(network string, laddr *net.UDPAddr) (net.PacketConn, error)
type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

func DefaultListenTCP(network string, laddr *net.TCPAddr) (net.Listener, error) {
	return net.ListenTCP(network, laddr)
}

func DefaultListenUDP(network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	return net.ListenUDP(network, laddr)
}
