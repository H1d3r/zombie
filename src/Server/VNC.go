package Server

import (
	"Zombie/src/Utils"
	"github.com/mitchellh/go-vnc"
	_ "github.com/mitchellh/go-vnc"
	"net"
	"strconv"
	"time"
)

func VNCConnect(User string, Password string, info Utils.IpInfo) (err error, result bool) {

	targetPort := strconv.Itoa(info.Port)

	target := info.Ip + ":" + targetPort

	conn, err := net.DialTimeout("tcp", target, time.Duration(Utils.Timeout)*time.Second)
	if err == nil {
		config := vnc.ClientConfig{
			Auth: []vnc.ClientAuth{
				&vnc.PasswordAuth{Password: Password},
			},
		}
		vncClient, err := vnc.Client(conn, &config)
		if err == nil {
			err = vncClient.Close()
			if err == nil {
				result = true
			}
		}
	}
	return err, result
}