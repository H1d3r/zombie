package ZbCrypto

import (
	"bytes"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

var XshellPath = map[string]string{
	"Xshell7": "C:\\Users\\%s\\Documents\\NetSarang Computer\\7",
	"Xshell6": "C:\\Users\\%s\\Documents\\NetSarang Computer\\6",
	"Xshell5": "C:\\Users\\%s\\Documents\\NetSarang Computer\\5",
}

func init_key(username, sid string) []byte {
	orgin := username + sid
	c := sha256.New()
	c.Write([]byte(orgin))
	return c.Sum(nil)
}

func DeXshell(cipertext string, username string, sid string) (string, error) {

	key := init_key(username, sid)

	passwd := make([]byte, len(cipertext))
	dedata, err := base64.StdEncoding.DecodeString(cipertext)
	if err != nil {
		return "", err
	}

	ciphertext := dedata[:len(dedata)-32]
	checksum := dedata[len(dedata)-32:]
	cipher1, _ := rc4.NewCipher(key)
	cipher1.XORKeyStream(passwd, ciphertext)
	password := strings.Trim(string(passwd), "\x00")

	h := sha256.New()
	h.Write([]byte(password))
	c1 := h.Sum(nil)

	if bytes.Equal(c1, checksum) {
		return password, nil
	}

	return "", fmt.Errorf("not equal with checksum")

}
