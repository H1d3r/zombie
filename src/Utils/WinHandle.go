package Utils

import (
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
