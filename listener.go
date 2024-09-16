package autoi2pd

import (
	"net"

	"github.com/eyedeekay/sam3"
	"github.com/xtaci/kcp-go/v5"
)

type autoi2pdListener struct {
	sam  *sam3.SAM
	cred *Credential
	sess *sam3.DatagramSession

	crypt kcp.BlockCrypt
	kcpln net.Listener
}

func (g *autoi2pdListener) Accept() (net.Conn, error) {
	conn, err := g.kcpln.Accept()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (g *autoi2pdListener) Close() error {
	err0 := g.kcpln.Close()
	err1 := g.sess.Close()
	err2 := g.sam.Close()
	if err0 != nil {
		return err0
	}
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return nil
}

func (g *autoi2pdListener) Addr() net.Addr {
	return g.kcpln.Addr()
}
func ListenOptions(options ...Option) (net.Listener, error) {
	opts := Options{
		Host:    "127.0.0.1",
		Port:    7656,
		PortUDP: 7655,

		Credential: nil,
		I2PConf:    DefaultI2PServerConf,

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

	kcpln, err := kcp.ServeConn(crypt, opts.KCPDataShards, opts.KCPParityShards, sess)
	if err != nil {
		sess.Close()
		sam.Close()
		return nil, err
	}

	ln := &autoi2pdListener{
		sam:  sam,
		cred: cred,
		sess: sess,

		crypt: crypt,
		kcpln: kcpln,
	}

	return ln, nil
}

func Listen() (net.Listener, error) {
	return ListenOptions()
}
