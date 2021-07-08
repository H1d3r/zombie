package Moudle

import (
	"Zombie/src/Core"
	"Zombie/src/Utils"
	"Zombie/src/ZbCrypto"
	"fmt"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"strconv"
	"strings"
	"time"
)

func DecryptAll(ctx *cli.Context) (err error) {
	Utils.File = ctx.String("OutputFile")
	//初始化文件

	if Utils.File != "null" {
		initFile(Utils.File)
		go Utils.QueryWrite2File(Utils.FileHandle, Utils.DDatach)

	}

	fmt.Println("Now start Navicat Decrypt")
	InfoList := ZbCrypto.ReadNavicatReg()

	for _, info := range InfoList {
		deres := fmt.Sprintf("Name: %v\tServer:%v\nIP:%v\tPort:%v\nUsername:%v\tPassword:%v\n", info.InfoName, info.Type, info.Ip, info.Port, info.Username, info.Password)
		Utils.DDatach <- deres
	}

	fmt.Println("Now start Xshell Decrypt")

	userinfo, err := Utils.GetCurInfo()
	if err != nil {
		return err
	}
	DecryptXManager(*userinfo)
	time.Sleep(1000 * time.Millisecond)
	return err
}

func DeXshell(ctx *cli.Context) (err error) {
	Utils.File = ctx.String("OutputFile")
	//初始化文件

	if Utils.File != "null" {
		initFile(Utils.File)
		go Utils.QueryWrite2File(Utils.FileHandle, Utils.DDatach)

	}

	curinfo := Utils.UserInfo{}
	if ctx.IsSet("username") {
		curinfo.Username = ctx.String("username")
	}

	if ctx.IsSet("sid") {
		curinfo.Sid = ctx.String("sid")
	}

	if curinfo.Sid == "" {
		userinfo, err := Utils.GetCurInfo()
		if err != nil {
			return err
		}

		curinfo.Username = userinfo.Username
		curinfo.Sid = userinfo.Sid
	}

	if ctx.IsSet("cipher") && ctx.IsSet("version") {

		plaintext, err := ZbCrypto.DeXshell(ctx.String("cipher"), ctx.Float64("version"), curinfo.Username, curinfo.Sid)
		if err != nil {
			return err
		}
		fmt.Println("Decrypt result is : " + plaintext)
		return nil
	}
	fmt.Println("Now start default decrypt")

	DecryptXManager(curinfo)
	time.Sleep(1000 * time.Millisecond)
	return err
}

func DeNavicat(ctx *cli.Context) (err error) {
	Utils.File = ctx.String("OutputFile")
	//初始化文件

	if Utils.File != "null" {
		initFile(Utils.File)
		go Utils.QueryWrite2File(Utils.FileHandle, Utils.DDatach)

	}

	if ctx.IsSet("cipher") {
		plaintext, err := ZbCrypto.DeNavicat(ctx.String("cipher"))
		if err != nil {
			return err
		}
		fmt.Println("Decrypt result is : " + plaintext)
	}

	InfoList := ZbCrypto.ReadNavicatReg()

	for _, info := range InfoList {
		deres := fmt.Sprintf("Name: %v\tServer:%v\nIP:%v\tPort:%v\nUsername:%v\tPassword:%v\n", info.InfoName, info.Type, info.Ip, info.Port, info.Username, info.Password)
		Utils.DDatach <- deres
	}

	time.Sleep(1000 * time.Millisecond)

	return err
}

func DecryptXManager(info Utils.UserInfo) {

	var XshellInfoList []*ZbCrypto.XshellInfo

	for _, path := range ZbCrypto.XshellPath {
		curpath := fmt.Sprintf(path, info.Username)
		files, _ := ioutil.ReadDir(curpath)
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".xsh") || strings.HasSuffix(f.Name(), ".xfp") {

				var xsinfo []string
				res := &ZbCrypto.XshellInfo{}
				fin, _ := Core.GetUAList(curpath + "\\" + f.Name())

				for _, i := range fin {
					i = strings.Replace(i, "\r", "", -1)
					i = strings.Replace(i, "\x00", "", -1)
					xsinfo = append(xsinfo, i)
				}
				XshellInfo := ZbCrypto.HandleXsh(xsinfo, res)
				XshellInfo.Name = f.Name()[:len(f.Name())-4]
				version, err := strconv.ParseFloat(XshellInfo.Version, 64)
				if err == nil {
					XshellInfo.Plain, err = ZbCrypto.DeXshell(XshellInfo.Cipher, version, info.Username, info.Sid)
					if err != nil {
						XshellInfo.Plain = "Decrypt failed"
					}
				}
				XshellInfoList = append(XshellInfoList, XshellInfo)
			}

		}
		for _, res := range XshellInfoList {
			XManagerInfo := fmt.Sprintf("Find %s:\nVersion:%s\nUsername: %s\nCipher:%s\nPassword:%s\n\n", res.Name, res.Version, res.UserName, res.Cipher, res.Plain)
			Utils.DDatach <- XManagerInfo
		}
	}
}
