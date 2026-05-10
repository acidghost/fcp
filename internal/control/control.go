package control

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/acidghost/fcp/internal/log"
	"github.com/acidghost/fcp/internal/protocol"
)

const MaxMessageSize = 65_536

var (
	ErrConnectionClosed = errors.New("connection closed by peer")
	ErrMessageTooLarge  = errors.New("message too large")
)

type Connection struct {
	conn net.Conn
	r    *bufio.Reader
	wMu  sync.Mutex
}

func NewConnection(conn net.Conn) *Connection {
	return &Connection{conn: conn, r: bufio.NewReader(conn)}
}

func Dial(addr net.Addr, timeout time.Duration) (*Connection, error) {
	log.Debug("dialing", "network", addr.Network(), "addr", addr.String(), "timeout", timeout)
	netConn, err := net.DialTimeout(addr.Network(), addr.String(), timeout)
	if err != nil {
		log.Warn("dial failed", "addr", addr.String(), "err", err)
		return nil, err
	}
	log.Debug("dial succeeded", "addr", addr.String())
	return NewConnection(netConn), nil
}

func DialTCP(addr net.TCPAddr, timeout time.Duration) (*Connection, error) {
	return Dial(&addr, timeout)
}

func (c *Connection) Recv() (protocol.Message, error) {
	return ReadMessage(c.r)
}

func (c *Connection) Send(msg protocol.Message) error {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	return WriteMessage(c.conn, msg)
}

func (c *Connection) Close() error {
	log.Debug("closing connection", "remote", c.conn.RemoteAddr().String())
	return c.conn.Close()
}

func (c *Connection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func ReadMessage(r *bufio.Reader) (protocol.Message, error) {
	line, err := readBoundedLine(r)
	if err != nil {
		if !errors.Is(err, ErrConnectionClosed) {
			log.Warn("failed to read message", "err", err)
		}
		return nil, err
	}
	msg, err := protocol.UnmarshalMessage(line)
	if err != nil {
		log.Warn("failed to unmarshal message", "err", err, "data", string(line))
		return nil, err
	}
	return msg, nil
}

func WriteMessage(w io.Writer, msg protocol.Message) error {
	data, err := protocol.MarshalMessage(msg)
	if err != nil {
		log.Error("failed to marshal message", "type", fmt.Sprintf("%T", msg), "err", err)
		return err
	}
	if len(data) > MaxMessageSize {
		log.Error("message too large", "type", fmt.Sprintf("%T", msg), "size", len(data), "max", MaxMessageSize)
		return fmt.Errorf("%w: %d bytes exceeds %d", ErrMessageTooLarge, len(data), MaxMessageSize)
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err = w.Write([]byte{'\n'})
	return err
}

func readBoundedLine(r *bufio.Reader) ([]byte, error) {
	line := make([]byte, 0, 256)
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(line) == 0 {
					return nil, ErrConnectionClosed
				}
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if b == '\n' {
			return line, nil
		}
		line = append(line, b)
		if len(line) > MaxMessageSize {
			drainLine(r)
			return nil, fmt.Errorf("%w: exceeded %d bytes", ErrMessageTooLarge, MaxMessageSize)
		}
	}
}

func drainLine(r *bufio.Reader) {
	for {
		b, err := r.ReadByte()
		if err != nil || b == '\n' {
			return
		}
	}
}
