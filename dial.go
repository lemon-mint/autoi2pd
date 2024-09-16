package autoi2pd

import (
	"net"
	"time"

	"github.com/eyedeekay/sam3"
	"github.com/xtaci/kcp-go/v5"
)

type autoi2pdConn struct {
	sam  *sam3.SAM
	sess *sam3.DatagramSession
	cred *Credential

	crypt   kcp.BlockCrypt
	kcpConn net.Conn
}

func (c *autoi2pdConn) Read(b []byte) (int, error) {
	return c.kcpConn.Read(b)
}

func (c *autoi2pdConn) Write(b []byte) (int, error) {
	return c.kcpConn.Write(b)
}

func (c *autoi2pdConn) Close() error {
	c.kcpConn.Close()
	c.sess.Close()
	c.sam.Close()
	return nil
}

func (c *autoi2pdConn) LocalAddr() net.Addr {
	return c.kcpConn.LocalAddr()
}

func (c *autoi2pdConn) RemoteAddr() net.Addr {
	return c.kcpConn.RemoteAddr()
}

func (c *autoi2pdConn) SetDeadline(t time.Time) error {
	return c.kcpConn.SetDeadline(t)
}

func (c *autoi2pdConn) SetReadDeadline(t time.Time) error {
	return c.kcpConn.SetReadDeadline(t)
}

func (c *autoi2pdConn) SetWriteDeadline(t time.Time) error {
	return c.kcpConn.SetWriteDeadline(t)
}

func DialOptions(dest string, options ...Option) (net.Conn, error) {
	opts := Options{
		Host:    "127.0.0.1",
		Port:    7656,
		PortUDP: 7655,

		Credential: nil,
		I2PConf:    DefaultI2PClientConf,

		PSK:             defaultPSK[:],
		KCPDataShards:   10,
		KCPParityShards: 3,
	}
	for _, o := range options {
		if o != nil {
			o(&opts)
		}
	}

	sam, sess, cred, crypt, err := createDatagramSession(&opts)
	if err != nil {
		return nil, err
	}

	destAddr, err := sam.Lookup(dest)
	if err != nil {
		sess.Close()
		sam.Close()
		return nil, err
	}

	kcpConn, err := kcp.NewConn2(destAddr, crypt, opts.KCPDataShards, opts.KCPParityShards, sess)
	if err != nil {
		sess.Close()
		sam.Close()
		return nil, err
	}

	c := &autoi2pdConn{
		sam:  sam,
		sess: sess,
		cred: cred,

		crypt:   crypt,
		kcpConn: kcpConn,
	}

	return c, nil
}

func Dial(dest string) (net.Conn, error) {
	return DialOptions(dest)
}
