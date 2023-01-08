package incominghandshaker

import (
	"io"
	"net"
	"time"

	"github.com/cenkalti/rain/internal/btconn"
	"github.com/cenkalti/rain/internal/logger"
	"github.com/cenkalti/rain/internal/mse"
)

// IncomingHandshaker does the BitTorrent protocol handshake on an incoming connection.
type IncomingHandshaker struct {
	Conn       net.Conn
	Addr       net.Addr
	PeerID     [20]byte
	Extensions [8]byte
	Cipher     mse.CryptoMethod
	Error      error

	closeC chan struct{}
	doneC  chan struct{}
}

// New returns a new IncomingHandshaker for a net.Conn.
func New(conn net.Conn) *IncomingHandshaker {
	// keep a reference around as it can get nulled (e.g. due to a disconnect)
	addr := conn.RemoteAddr()
	if a, ok := addr.(*net.TCPAddr); ok {
		addrCopy := *a
		addr = &addrCopy
	}
	return &IncomingHandshaker{
		Conn:   conn,
		Addr:   addr,
		closeC: make(chan struct{}),
		doneC:  make(chan struct{}),
	}
}

// Close the IncomingHandshaker. Also closes the underlying connection if there is an ongoing handshake operation.
func (h *IncomingHandshaker) Close() {
	close(h.closeC)
	<-h.doneC
}

// Run the handshaker goroutine.
func (h *IncomingHandshaker) Run(peerID [20]byte, getSKeyFunc func([20]byte) []byte, checkInfoHashFunc func([20]byte) bool, resultC chan *IncomingHandshaker, timeout time.Duration, ourExtensions [8]byte, forceIncomingEncryption bool) {
	defer close(h.doneC)
	defer func() {
		select {
		case resultC <- h:
		case <-h.closeC:
			h.Conn.Close()
		}
	}()

	log := logger.New("conn <- " + h.Conn.RemoteAddr().String())

	conn, cipher, peerExtensions, peerID, _, err := btconn.Accept(
		h.Conn, timeout, getSKeyFunc, forceIncomingEncryption, checkInfoHashFunc, ourExtensions, peerID)
	if err != nil {
		if err == io.EOF {
			log.Debug("peer has closed the connection: EOF")
		} else if err == io.ErrUnexpectedEOF {
			log.Debug("peer has closed the connection: Unexpected EOF")
		} else if _, ok := err.(*net.OpError); ok {
			log.Debugln("net operation error:", err)
		} else if _, ok := err.(*btconn.HandshakeError); ok {
			log.Debugln("protocol error:", err)
		} else {
			log.Debugln("cannot complete incoming handshake:", err)
		}
		h.Error = err
		return
	}
	log.Debugf("Connection accepted. (cipher=%s extensions=%x client=%q)", cipher, peerExtensions, peerID[:8])

	h.Conn = conn
	h.PeerID = peerID
	h.Extensions = peerExtensions
	h.Cipher = cipher
}
