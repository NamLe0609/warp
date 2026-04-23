package cli

import (
	"context"
	"crypto/tls"
	"net"
	stdHttp "net/http"
	"os"
	"time"

	"github.com/minio/cli"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func clientTransportHTTP3(ctx *cli.Context, localIP string) stdHttp.RoundTripper {
	// Keep TLS config - same as tls/ktls
	tlsConfig := &tls.Config{
		RootCAs: mustGetSystemCertPool(),
		// Can't use SSLv3 because of POODLE and BEAST
		// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
		// Can't use TLSv1.1 because of RC4 cipher usage
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: ctx.Bool("insecure"),
		ClientSessionCache: tls.NewLRUClientSessionCache(1024), // up to 1024 nodes
		// HTTP/3 uses ALPN "h3" instead of "h2"
		NextProtos: []string{"h3"},
	}

	if ctx.Bool("debug") {
		tlsConfig.KeyLogWriter = os.Stdout
	}

	// Configure QUIC - similar to http.Transport settings
	quicConfig := &quic.Config{
		MaxIdleTimeout:        90 * time.Second,
		MaxIncomingStreams:    int64(ctx.Int("concurrent")),
		MaxIncomingUniStreams: -1, // Disable unidirectional streams
		KeepAlivePeriod:       10 * time.Second,

		// Buffer sizes - quic-go uses different mechanism than TCP buffers
		// So set initial stream receive window
		InitialStreamReceiveWindow:     uint64(ctx.Int("rcvbuf")) * 1024,
		InitialConnectionReceiveWindow: uint64(ctx.Int("rcvbuf")) * 1024 * 2,
	}

	h3Transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
	}

	// Handle local IP binding - similar to other transports
	if localIP != "" {
		// Bind UDP connection to specific local IP
		localUDPAddr, err := net.ResolveUDPAddr("udp", localIP+":0")
		if err != nil {
			// Fall back to default binding
			return h3Transport
		}

		udpConn, err := net.ListenUDP("udp", localUDPAddr)
		if err != nil {
			return h3Transport
		}

		quicTransport := &quic.Transport{
			Conn: udpConn,
		}

		// Set custom dial function that uses our bound transport
		h3Transport.Dial = func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
			remoteAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return quicTransport.Dial(ctx, remoteAddr, tlsConf, quicConf)
		}
	}

	return h3Transport
}
