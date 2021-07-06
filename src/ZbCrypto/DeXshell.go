package ZbCrypto

import (
	"Zombie/src/Utils"
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

var XshellPath = map[string]string{
	"Xshell7": "C:\\Users\\%s\\Documents\\NetSarang Computer\\7\\Xshell\\Sessions",
	"Xshell6": "C:\\Users\\%s\\Documents\\NetSarang Computer\\6\\Xshell\\Sessions",
	"Xshell5": "C:\\Users\\%s\\Documents\\NetSarang Computer\\5\\Xshell\\Sessions",
}

type XshellInfo struct {
	Name     string
	Version  string
	UserName string
	Cipher   string
	Plain    string
}

func init_key(username, sid string) []byte {
	orgin := username + sid
	c := sha256.New()
	c.Write([]byte(orgin))
	return c.Sum(nil)
}

func DeXshell(cipertext string, version float64, username, sid string) (string, error) {
	if sid == "" {
		userinfo, err := Utils.GetCurInfo()
		if err != nil {
			return "", err
		}

		username = userinfo.Username
		sid = userinfo.Sid
	}

	var key []byte

	if 0 < version && version < 5.1 {
		ret := md5.Sum([]byte("!X@s#h$e%l^l&"))
		key = ret[:]
	} else if 5.1 <= version && version <= 5.2 {
		c := sha256.New()
		c.Write([]byte(sid))
		key = c.Sum(nil)
	} else if 5.2 < version && version < 7 {
		key = init_key(username, sid)
	} else {
		return "", fmt.Errorf("version too high,it can't decrypt over Xshell7")
	}

	passwd := make([]byte, len(cipertext))
	dedata, err := base64.StdEncoding.DecodeString(cipertext)
	if err != nil {
		return "", err
	}

	cipher1, _ := rc4.NewCipher(key)

	if version < 5.1 {
		cipher1.XORKeyStream(passwd, dedata)
		return strings.Trim(string(passwd), "\x00"), nil
	} else {
		ciphertext := dedata[:len(dedata)-32]
		checksum := dedata[len(dedata)-32:]

		cipher1.XORKeyStream(passwd, ciphertext)
		password := strings.Trim(string(passwd), "\x00")

		h := sha256.New()
		h.Write([]byte(password))
		c1 := h.Sum(nil)

		if bytes.Equal(c1, checksum) {
			return password, nil
		}
	}

	return "", fmt.Errorf("not equal with checksum")

}

func HandleXsh(XshInfo []string, res *XshellInfo) *XshellInfo {
	for _, info := range XshInfo {
		if strings.HasPrefix(info, "UserName") {
			res.UserName = info[len("UserName")+1:]
		} else if strings.HasPrefix(info, "Password") {
			res.Cipher = info[len("Password")+1:]
		} else if strings.HasPrefix(info, "Version") {
			res.Version = info[len("Version")+1:]
		}

	}
	return res
}
