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

package ztunnel

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// testTimeout is the per-test deadline used when waiting for goroutines.
const testTimeout = 2 * time.Second

// mockSocks5Server is a minimal SOCKS5 server used for testing DialSocks5 and
// the full proxy pipeline.  It supports only "no auth" and CONNECT (IPv4 and
// domain-name address types).
type mockSocks5Server struct {
	listener net.Listener
	// connectedDst records the last destination address received in a CONNECT.
	connectedDst chan string
}

func newMockSocks5Server(t *testing.T) *mockSocks5Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create mock SOCKS5 server: %v", err)
	}
	s := &mockSocks5Server{
		listener:     ln,
		connectedDst: make(chan string, 1),
	}
	go s.serve(t)
	return s
}

func (s *mockSocks5Server) Addr() string { return s.listener.Addr().String() }

func (s *mockSocks5Server) serve(t *testing.T) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handleConn(t, conn)
	}
}

func (s *mockSocks5Server) handleConn(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()

	// --- greeting ---
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	nmethods := int(greeting[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// Accept no-auth
	conn.Write([]byte{0x05, socks5NoAuth}) //nolint:errcheck

	// --- CONNECT request ---
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}

	var host string
	switch header[3] {
	case 0x01: // IPv4
		buf := make([]byte, 6) // 4 bytes IP + 2 bytes port
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		ip := net.IP(buf[:4])
		port := int(buf[4])<<8 | int(buf[5])
		host = fmt.Sprintf("%s:%d", ip.String(), port)
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		nameBuf := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(conn, nameBuf); err != nil {
			return
		}
		port := int(nameBuf[len(nameBuf)-2])<<8 | int(nameBuf[len(nameBuf)-1])
		host = fmt.Sprintf("%s:%d", string(nameBuf[:len(nameBuf)-2]), port)
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
		return
	}

	// Record the destination that was requested.
	select {
	case s.connectedDst <- host:
	default:
	}

	// Success reply: VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck

	// Echo data back to the client so we can test end-to-end forwarding.
	io.Copy(conn, conn) //nolint:errcheck
}

func (s *mockSocks5Server) close() { s.listener.Close() }

// ---------------------------------------------------------------------------

// TestDialSocks5_IPv4 verifies that DialSocks5 successfully completes the
// SOCKS5 handshake when given an IPv4 destination address.
func TestDialSocks5_IPv4(t *testing.T) {
	srv := newMockSocks5Server(t)
	defer srv.close()

	conn, err := DialSocks5(srv.Addr(), "1.2.3.4", 8080)
	assert.NoError(t, err)
	if conn != nil {
		defer conn.Close()
	}

	// Verify the mock server recorded the correct destination.
	select {
	case dst := <-srv.connectedDst:
		assert.Equal(t, "1.2.3.4:8080", dst)
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for SOCKS5 server to record destination")
	}
}

// TestDialSocks5_Domain verifies that DialSocks5 uses the domain-name address
// type (ATYP=3) when the destination is not a numeric IPv4 address.
func TestDialSocks5_Domain(t *testing.T) {
	srv := newMockSocks5Server(t)
	defer srv.close()

	conn, err := DialSocks5(srv.Addr(), "example.com", 443)
	assert.NoError(t, err)
	if conn != nil {
		defer conn.Close()
	}

	select {
	case dst := <-srv.connectedDst:
		assert.Equal(t, "example.com:443", dst)
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for SOCKS5 server to record destination")
	}
}

// TestDialSocks5_DataForwarding checks that data written to the returned conn
// is forwarded through the SOCKS5 tunnel and echoed back by the mock server.
func TestDialSocks5_DataForwarding(t *testing.T) {
	srv := newMockSocks5Server(t)
	defer srv.close()

	conn, err := DialSocks5(srv.Addr(), "1.2.3.4", 9000)
	assert.NoError(t, err)
	if err != nil {
		return
	}
	defer conn.Close()

	payload := []byte("hello ztunnel")
	_, err = conn.Write(payload)
	assert.NoError(t, err)

	buf := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	_, err = io.ReadFull(conn, buf)
	assert.NoError(t, err)
	assert.Equal(t, payload, buf)
}

// TestDialSocks5_ServerError verifies that DialSocks5 returns an error when
// the SOCKS5 server replies with a non-zero reply code.
func TestDialSocks5_ServerError(t *testing.T) {
	// Start a server that always replies with "host unreachable" (0x04).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Consume greeting
		buf := make([]byte, 3)
		io.ReadFull(conn, buf) //nolint:errcheck
		// Send method selection
		conn.Write([]byte{0x05, 0x00}) //nolint:errcheck
		// Consume CONNECT request (10 bytes for IPv4)
		req := make([]byte, 10)
		io.ReadFull(conn, req) //nolint:errcheck
		// Reply: host unreachable
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
	}()

	_, err = DialSocks5(ln.Addr().String(), "1.2.3.4", 80)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "0x04")
}

// TestDialSocks5_ConnectionRefused verifies that DialSocks5 returns an error
// when the SOCKS5 proxy address is unreachable.
func TestDialSocks5_ConnectionRefused(t *testing.T) {
	_, err := DialSocks5("127.0.0.1:1", "1.2.3.4", 80)
	assert.Error(t, err)
}

// TestProxyBidirectional verifies that proxyBidirectional copies data in both
// directions between two net.Conn values, using in-memory net.Pipe connections.
func TestProxyBidirectional(t *testing.T) {
	aRemote, aLocal := net.Pipe()
	bRemote, bLocal := net.Pipe()

	go proxyBidirectional(aLocal, bLocal)

	msg1 := []byte("ping")
	msg2 := []byte("pong")

	// Write from the aRemote side; read on the bRemote side.
	go func() {
		aRemote.Write(msg1) //nolint:errcheck
	}()

	buf := make([]byte, len(msg1))
	bRemote.SetReadDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	_, err := io.ReadFull(bRemote, buf)
	assert.NoError(t, err)
	assert.Equal(t, msg1, buf)

	// Write from the bRemote side; read on the aRemote side.
	go func() {
		bRemote.Write(msg2) //nolint:errcheck
	}()

	buf2 := make([]byte, len(msg2))
	aRemote.SetReadDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	_, err = io.ReadFull(aRemote, buf2)
	assert.NoError(t, err)
	assert.Equal(t, msg2, buf2)

	// Clean up
	aRemote.Close()
	bRemote.Close()
}

// TestSocks5ReplyMessage checks that known SOCKS5 reply codes produce
// non-empty human-readable strings and that unknown codes return "unknown".
func TestSocks5ReplyMessage(t *testing.T) {
	knownCodes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	for _, code := range knownCodes {
		msg := socks5ReplyMessage(code)
		assert.NotEmpty(t, msg, "expected non-empty message for code 0x%02x", code)
		assert.NotEqual(t, "unknown", msg, "code 0x%02x should have a specific message", code)
	}
	assert.Equal(t, "unknown", socks5ReplyMessage(0xFF))
}

// TestGetOriginalDst_NonTCP verifies that GetOriginalDst returns an error when
// given a non-TCP connection (e.g., a net.Pipe conn).
func TestGetOriginalDst_NonTCP(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	_, err := GetOriginalDst(a)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not *net.TCPConn")
}
