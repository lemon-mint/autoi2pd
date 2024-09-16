package autoi2pd

import (
	"strconv"

	"github.com/eyedeekay/sam3"
	"github.com/rs/xid"
	"github.com/xtaci/kcp-go/v5"
)

func createDatagramSession(opts *Options) (*sam3.SAM, *sam3.DatagramSession, *Credential, kcp.BlockCrypt, error) {
	sam, err := sam3.NewSAM(opts.Host + ":" + strconv.Itoa(opts.Port))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if opts.Credential == nil {
		opts.Credential = &Credential{}
		opts.Credential.key, err = sam.NewKeys()
		if err != nil {
			sam.Close()
			return nil, nil, nil, nil, err
		}
	}

	sessID := xid.New().String()

	crypt, err := kcp.NewAESBlockCrypt(opts.PSK)
	if err != nil {
		sam.Close()
		return nil, nil, nil, nil, err
	}

	sess, err := sam.NewDatagramSession(sessID, opts.Credential.Key(), opts.I2PConf, opts.PortUDP)
	if err != nil {
		sam.Close()
		return nil, nil, nil, nil, err
	}

	return sam, sess, opts.Credential, crypt, nil
}
