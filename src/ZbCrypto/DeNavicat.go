package ZbCrypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/sys/windows/registry"
	"strconv"
)

var ServersRegPath = map[string]string{
	"MySQL Server":      "Software\\PremiumSoft\\Navicat\\Servers",
	"MariaDB Server":    "Software\\PremiumSoft\\NavicatMARIADB\\Servers",
	"MongoDB Server":    "Software\\PremiumSoft\\NavicatMONGODB\\Servers",
	"MSSQL Server":      "Software\\PremiumSoft\\NavicatMSSQL\\Servers",
	"OracleSQL Server":  "Software\\PremiumSoft\\NavicatOra\\Servers",
	"PostgreSQL Server": "Software\\PremiumSoft\\NavicatPG\\Servers",
	"SQLite Server":     "Software\\PremiumSoft\\NavicatSQLite\\Servers",
}

type NavicatInfo struct {
	InfoName string
	Ip       string
	Port     string
	Username string
	Password string
}

func ReadNavicatReg() (InfoList []NavicatInfo) {

	for _, path := range ServersRegPath {
		key, exists := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)

		if exists != nil {
			continue
		}
		keys, _ := key.ReadSubKeyNames(0)
		for _, key_subkey := range keys {
			// 输出所有子项的名字
			NewNavicatInfo := NavicatInfo{InfoName: key_subkey}
			subkey, subexists := registry.OpenKey(key, key_subkey, registry.ALL_ACCESS)
			if subexists != nil {
				continue
			}

			username, _, err := subkey.GetStringValue("UserName")
			if err == nil {
				NewNavicatInfo.Password = username
			}

			password, _, err := subkey.GetStringValue("Pwd")
			if err == nil {
				password, err = DeNavicat(password)
				if err != nil {
					NewNavicatInfo.Password = "Decrypt failed"
				} else {
					NewNavicatInfo.Password = password
				}

			}

			port, _, err := subkey.GetIntegerValue("Port")
			if err == nil {
				NewNavicatInfo.Port = strconv.Itoa(int(port))
			}

			ip, _, err := subkey.GetStringValue("Host")
			if err == nil {
				NewNavicatInfo.Ip = ip
			}

			InfoList = append(InfoList, NewNavicatInfo)

			subkey.Close()
		}
		key.Close()

	}
	return InfoList
}

func DeNavicat(cipherhex string) (string, error) {
	o := sha1.New()
	o.Write([]byte("3DC5CA39"))
	//key := hex.EncodeToString(o.Sum(nil))
	keyb := o.Sum(nil)
	key := string(keyb)
	//cipherhex := "8698D3EA9E000E993079A3697CA576A450DFAD"
	//cipherhex := "5658213B"

	iv := []byte("\xff\xff\xff\xff\xff\xff\xff\xff")

	hex_data, _ := hex.DecodeString(cipherhex)
	// 将 byte 转换 为字符串 输出结果
	cipher := string(hex_data)

	iv, err := BlowfishECBEncrypt(string(iv), key)
	//price := "root"
	//enc, err := BlowfishECBEncrypt(price, key)
	if err != nil {
		return "", nil
	}
	round, left := divmod(len(cipher))
	cv := iv

	var password string

	for i := 0; i < round; i++ {
		temp, err := BlowfishECBDecrypt([]byte(cipher[i*8:i*8+8]), keyb)
		if err != nil {
			return "", err
		}
		temp = byteByXOR(temp, cv)
		password += string(temp)
		cv = byteByXOR(cv, hex_data[i*8:i*8+8])
	}

	if left != 0 {
		cv, err = BlowfishECBEncrypt(string(cv), key)
		if err != nil {
			fmt.Println("-------err: ", err)
		}
		password += string(byteByXOR(hex_data[8*round:], cv[:left]))
	}
	return password, nil
}

func byteByXOR(message []byte, keywords []byte) []byte {
	messageLen := len(message)
	keywordsLen := len(keywords)

	var result []byte
	for i := 0; i < messageLen; i++ {
		result = append(result, message[i]^keywords[i%keywordsLen])
	}
	return result
}

func BlowfishECBEncrypt(src, key string) ([]byte, error) {
	block, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	if src == "" {
		return nil, errors.New("plain content empty")
	}
	ecb := NewECBEncrypter(block)
	content := []byte(src)
	//content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	return crypted, nil
}

func BlowfishECBDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	blockMode := NewECBDecrypter(block)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	return origData, nil
}

type ECB struct {
	b         cipher.Block
	blockSize int
}

func NewECB(b cipher.Block) *ECB {
	return &ECB{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ECBEncrypter ECB

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ECBEncrypter)(NewECB(b))
}
func (x *ECBEncrypter) BlockSize() int { return x.blockSize }
func (x *ECBEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ECBDecrypter ECB

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ECBDecrypter)(NewECB(b))
}
func (x *ECBDecrypter) BlockSize() int {
	return x.blockSize
}
func (x *ECBDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// PKCS5Padding _
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS5UnPadding _
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func divmod(plainlen int) (round, left int) {
	round = plainlen / 8
	left = plainlen % 8
	return round, left
}
