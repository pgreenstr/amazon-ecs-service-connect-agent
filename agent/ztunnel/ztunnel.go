// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

// Package ztunnel provides a transparent TCP-to-SOCKS5 proxy that bridges ECS
// proxy traffic interception (via iptables redirect) with an Istio ZTunnel
// sidecar's SOCKS5 interface.
//
// When the ECS proxy configuration redirects outbound application traffic to a
// local port via iptables, this proxy:
//  1. Accepts the intercepted TCP connection on that port.
//  2. Recovers the original destination address using the SO_ORIGINAL_DST
//     socket option (set by the kernel's netfilter/iptables redirect rule).
//  3. Dials ZTunnel's SOCKS5 endpoint and issues a SOCKS5 CONNECT for the
//     original destination.
//  4. Copies data bidirectionally between the application connection and the
//     ZTunnel connection.
package ztunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

// SO_ORIGINAL_DST is the Linux socket option used to retrieve the original
// destination address of a connection that was redirected by iptables REDIRECT
// or DNAT rules.
const SO_ORIGINAL_DST = 80

// socks5NoAuth is the SOCKS5 "no authentication required" method byte.
const socks5NoAuth = 0x00

// Proxy is a transparent TCP-to-SOCKS5 forwarding proxy.
//
// It listens on ListenAddr for TCP connections that have been redirected by
// iptables, recovers each connection's original destination via SO_ORIGINAL_DST,
// and tunnels the connection through a SOCKS5 CONNECT request to ZTunnelAddr.
type Proxy struct {
	// ListenAddr is the TCP address (host:port) on which the proxy accepts
	// intercepted connections, e.g. "0.0.0.0:15001".
	ListenAddr string

	// ZTunnelAddr is the host:port of the ZTunnel sidecar's SOCKS5 interface,
	// e.g. "127.0.0.1:15080".
	ZTunnelAddr string
}

// Run starts the proxy listener and blocks until the listener is closed.
// Each accepted connection is handled in its own goroutine.
func (p *Proxy) Run() error {
	ln, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("ztunnel proxy: listen on %s: %w", p.ListenAddr, err)
	}
	defer ln.Close()

	log.Infof("ZTunnel proxy: listening on %s, forwarding via SOCKS5 to %s", p.ListenAddr, p.ZTunnelAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// The listener was closed; treat this as a clean exit.
			return fmt.Errorf("ztunnel proxy: accept: %w", err)
		}
		go p.handleConn(conn)
	}
}

// handleConn processes a single intercepted connection: it resolves the
// original destination and sets up bidirectional forwarding through ZTunnel.
func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	origDst, err := GetOriginalDst(conn)
	if err != nil {
		log.Errorf("ZTunnel proxy: get original destination: %v", err)
		return
	}

	log.Debugf("ZTunnel proxy: forwarding connection to %s via ZTunnel SOCKS5 at %s",
		origDst.String(), p.ZTunnelAddr)

	upstream, err := DialSocks5(p.ZTunnelAddr, origDst.IP.String(), origDst.Port)
	if err != nil {
		log.Errorf("ZTunnel proxy: SOCKS5 dial to ZTunnel (%s) for destination %s: %v",
			p.ZTunnelAddr, origDst.String(), err)
		return
	}
	defer upstream.Close()

	proxyBidirectional(conn, upstream)
}

// proxyBidirectional copies data in both directions between two net.Conn
// values, closing both connections when either side signals EOF or an error.
func proxyBidirectional(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			log.Debugf("ZTunnel proxy: copy error: %v", err)
		}
		// Signal the other goroutine that this direction is done.
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite() //nolint:errcheck
		}
	}

	go copy(a, b)
	go copy(b, a)
	wg.Wait()
}

// GetOriginalDst retrieves the original destination address of a TCP
// connection that was redirected by an iptables REDIRECT (or DNAT) rule.
//
// On Linux, the kernel records the pre-NAT destination address in the
// connection tracking entry and exposes it via the SO_ORIGINAL_DST socket
// option (value 80) on the IPPROTO_IP level.
//
// Only IPv4 is supported; for IPv6 use IP6T_SO_ORIGINAL_DST on SOL_IPV6.
func GetOriginalDst(conn net.Conn) (*net.TCPAddr, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("connection is not *net.TCPConn")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("SyscallConn: %w", err)
	}

	var origDst *net.TCPAddr
	var innerErr error

	err = rawConn.Control(func(fd uintptr) {
		// sockaddr_in is 16 bytes on Linux:
		//   2 bytes  sa_family  (AF_INET = 2)
		//   2 bytes  sin_port   (big-endian)
		//   4 bytes  sin_addr
		//   8 bytes  padding
		var addr [16]byte
		addrLen := uint32(len(addr))

		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_IP),
			uintptr(SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&addr[0])),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno != 0 {
			innerErr = fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", errno)
			return
		}

		port := int(addr[2])<<8 | int(addr[3])
		ip := net.IP(addr[4:8]).To4()
		origDst = &net.TCPAddr{IP: ip, Port: port}
	})
	if err != nil {
		return nil, fmt.Errorf("rawConn.Control: %w", err)
	}
	if innerErr != nil {
		return nil, innerErr
	}
	return origDst, nil
}

// DialSocks5 connects to the SOCKS5 proxy at proxyAddr and issues a CONNECT
// request to reach dstHost:dstPort.  It returns the established net.Conn
// ready for data transfer, or an error.
//
// Only the "no authentication" method (0x00) is used.
func DialSocks5(proxyAddr, dstHost string, dstPort int) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial SOCKS5 proxy %s: %w", proxyAddr, err)
	}

	if err := socks5Handshake(conn, dstHost, dstPort); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// socks5Handshake performs the SOCKS5 greeting + CONNECT sequence on conn,
// targeting dstHost:dstPort.
func socks5Handshake(conn net.Conn, dstHost string, dstPort int) error {
	// ── 1. Greeting ──────────────────────────────────────────────────────
	// VER(1)=5  NMETHODS(1)=1  METHODS[0]=0 (NO AUTH)
	greeting := []byte{0x05, 0x01, socks5NoAuth}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("SOCKS5 greeting write: %w", err)
	}

	// Server selects a method: VER(1) METHOD(1)
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("SOCKS5 greeting read: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("SOCKS5 greeting: unexpected version %d", resp[0])
	}
	if resp[1] != socks5NoAuth {
		return fmt.Errorf("SOCKS5 greeting: server requires unsupported auth method 0x%02x", resp[1])
	}

	// ── 2. CONNECT request ───────────────────────────────────────────────
	// Prefer sending the raw IPv4 address (ATYP=1) when possible; fall back
	// to domain name encoding (ATYP=3) otherwise.
	var request []byte
	if ip := net.ParseIP(dstHost).To4(); ip != nil {
		// ATYP=0x01 (IPv4): VER CMD RSV ATYP [4-byte IP] [2-byte port]
		request = make([]byte, 10)
		request[0] = 0x05 // VER
		request[1] = 0x01 // CMD = CONNECT
		request[2] = 0x00 // RSV
		request[3] = 0x01 // ATYP = IPv4
		copy(request[4:8], ip)
		binary.BigEndian.PutUint16(request[8:10], uint16(dstPort))
	} else {
		// ATYP=0x03 (domain): VER CMD RSV ATYP LEN [hostname] [2-byte port]
		hostBytes := []byte(dstHost)
		request = make([]byte, 7+len(hostBytes))
		request[0] = 0x05
		request[1] = 0x01
		request[2] = 0x00
		request[3] = 0x03 // ATYP = domain name
		request[4] = byte(len(hostBytes))
		copy(request[5:], hostBytes)
		binary.BigEndian.PutUint16(request[5+len(hostBytes):], uint16(dstPort))
	}

	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT write: %w", err)
	}

	// ── 3. CONNECT reply ─────────────────────────────────────────────────
	// VER(1) REP(1) RSV(1) ATYP(1) …
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT reply header read: %w", err)
	}
	if header[0] != 0x05 {
		return fmt.Errorf("SOCKS5 CONNECT reply: unexpected version %d", header[0])
	}
	if header[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT reply: server reported error code 0x%02x: %s",
			header[1], socks5ReplyMessage(header[1]))
	}

	// Consume the bound address from the reply (we don't use it).
	switch header[3] {
	case 0x01: // IPv4: 4 bytes + 2-byte port
		tail := make([]byte, 6)
		if _, err := io.ReadFull(conn, tail); err != nil {
			return fmt.Errorf("SOCKS5 CONNECT reply (IPv4 tail) read: %w", err)
		}
	case 0x03: // domain: 1-byte length + N bytes + 2-byte port
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("SOCKS5 CONNECT reply (domain length) read: %w", err)
		}
		tail := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(conn, tail); err != nil {
			return fmt.Errorf("SOCKS5 CONNECT reply (domain tail) read: %w", err)
		}
	case 0x04: // IPv6: 16 bytes + 2-byte port
		tail := make([]byte, 18)
		if _, err := io.ReadFull(conn, tail); err != nil {
			return fmt.Errorf("SOCKS5 CONNECT reply (IPv6 tail) read: %w", err)
		}
	default:
		return fmt.Errorf("SOCKS5 CONNECT reply: unknown address type 0x%02x", header[3])
	}

	return nil
}

// socks5ReplyMessage returns a human-readable description of a SOCKS5 reply
// code (RFC 1928 §6).
func socks5ReplyMessage(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown"
	}
}
