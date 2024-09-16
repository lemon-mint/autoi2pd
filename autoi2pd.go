package autoi2pd

import (
	"bytes"
	"crypto/sha256"

	"github.com/eyedeekay/i2pkeys"
)

var DefaultI2PServerConf = []string{"inbound.length=1", "outbound.length=1",
	"inbound.lengthVariance=0", "outbound.lengthVariance=0",
	"inbound.backupQuantity=3", "outbound.backupQuantity=3",
	"inbound.quantity=5", "outbound.quantity=5"}

var DefaultI2PClientConf = []string{"inbound.length=1", "outbound.length=1",
	"inbound.lengthVariance=0", "outbound.lengthVariance=0",
	"inbound.backupQuantity=2", "outbound.backupQuantity=2",
	"inbound.quantity=3", "outbound.quantity=3"}

type Credential struct {
	key i2pkeys.I2PKeys
}

func LoadCredential(b []byte) (*Credential, error) {
	key, err := i2pkeys.LoadKeysIncompat(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return &Credential{key}, nil
}

func StoreCredential(c *Credential) ([]byte, error) {
	var b bytes.Buffer
	err := i2pkeys.StoreKeysIncompat(c.key, &b)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (c *Credential) Key() i2pkeys.I2PKeys {
	return c.key
}

type Options struct {
	Host    string // default to 127.0.0.1
	Port    int    // default to 7656
	PortUDP int    // default to 0

	Credential *Credential // if nil, new credential will be generated
	I2PConf    []string    // if nil, DefaultI2PClientConf and DefaultI2PServerConf will be used

	PSK             []byte // if nil, default PSK will be used
	KCPDataShards   int    // default to 10
	KCPParityShards int    // default to 3
}

type Option func(*Options)

func WithSAMHost(addr string) Option {
	return func(o *Options) {
		o.Host = addr
	}
}

func WithSAMPort(port int) Option {
	return func(o *Options) {
		o.Port = port
	}
}

func WithSAMPortUDP(port int) Option {
	return func(o *Options) {
		o.PortUDP = port
	}
}

func WithCredential(c *Credential) Option {
	return func(o *Options) {
		o.Credential = c
	}
}

func WithPSK(psk []byte) Option {
	return func(o *Options) {
		if len(psk) != 32 {
			hash := sha256.Sum256(psk)
			psk = hash[:]
		}
		o.PSK = psk
	}
}

var defaultPSK = sha256.Sum256([]byte("autoi2pd compatibility version v1"))
