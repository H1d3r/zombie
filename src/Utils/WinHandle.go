package Utils

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"os/user"
	"strings"
)

type UserInfo struct {
	Username string
	Sid      string
}

func GetCurInfo() (*UserInfo, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	Curuser := UserInfo{}
	Curuser.Username = u.Username

	if strings.Contains(Curuser.Username, "\\") {
		Namelist := strings.Split(Curuser.Username, "\\")
		Curuser.Username = Namelist[1]
	}

	Curuser.Sid = u.Uid
	return &Curuser, nil
}

func GetAllUser() ([]UserInfo, error) {
	var userlist []UserInfo
	path := "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
	key, exists := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)

	if exists != nil {
		fmt.Println(exists)
	}
	keys, _ := key.ReadSubKeyNames(0)

	for _, key_subkey := range keys {
		SplitSid := strings.Split(key_subkey, "-")
		if len(SplitSid) == 8 {
			NowUser := UserInfo{}
			curuser, _ := user.LookupId(key_subkey)
			NowUser.Username = curuser.Username
			if strings.Contains(NowUser.Username, "\\") {
				Namelist := strings.Split(NowUser.Username, "\\")
				NowUser.Username = Namelist[1]
			}

			NowUser.Sid = curuser.Uid
			userlist = append(userlist, NowUser)
		}
	}
	return userlist, nil
}
