package Moudle

import (
	"Zombie/src/Core"
	"Zombie/src/Utils"
	"fmt"
	"github.com/urfave/cli/v2"
	"os"
	"strconv"
	"strings"
)

func Exec(ctx *cli.Context) (err error) {
	var CurServer string
	var CurtaskList []Utils.ScanTask

	if ctx.IsSet("InputFile") {
		TestList, _ := Core.GetUAList(ctx.String("InputFile"))

		for _, test := range TestList {
			la := strings.Split(test, "\t")

			if len(la) == 6 {
				Curtask := Utils.ScanTask{
					Username: strings.Split(la[2], ":")[1],
					Password: strings.Split(la[3], ":")[1],
					Server:   la[4],
				}
				IpPo := strings.Split(la[0], ":")
				Curtask.Info.Ip = IpPo[0]
				Curtask.Info.Port, _ = strconv.Atoi(IpPo[1])
				CurtaskList = append(CurtaskList, Curtask)
			}
			continue
		}

	} else {
		if strings.Contains(ctx.String("ip"), ",") {
			fmt.Println("Exec Moudle only support single ip")
			os.Exit(0)
		}

		IpSlice := Core.GetIpList(ctx.String("ip"))

		Ip := IpSlice[0]
		if ctx.IsSet("server") {
			ServerName := strings.ToUpper(ctx.String("server"))
			if _, ok := Utils.ExecPort[ServerName]; ok {
				CurServer = ctx.String("server")
			} else {
				fmt.Println("the Database isn't be supported")
				os.Exit(0)
			}

		} else if strings.Contains(Ip, ":") {
			Temp := strings.Split(Ip, ":")
			Sport := Temp[1]
			port, err := strconv.Atoi(Sport)
			if err != nil {
				fmt.Println("Please check your address")
				os.Exit(0)
			}

			if _, ok := Utils.ExecServer[port]; ok {
				CurServer = Utils.PortServer[port]
				fmt.Println("Use default server")
			} else {
				fmt.Println("Please input the type of Database")
				os.Exit(0)
			}
		} else {
			fmt.Println("Please input the type of Database")
			os.Exit(0)
		}

		CurServer = strings.ToUpper(CurServer)

		IpList := Core.GetIpInfoList(IpSlice, CurServer)

		Curtask := Utils.ScanTask{
			Info:     IpList[0],
			Username: ctx.String("username"),
			Password: ctx.String("password"),
			Server:   CurServer,
		}
		CurtaskList = append(CurtaskList, Curtask)

	}

	for _, Curtask := range CurtaskList {

		CurCon := Core.ExecDispatch(Curtask)

		alive := CurCon.Connect()

		if !alive {
			fmt.Printf("can't connect to db")
			os.Exit(0)
		}

		IsAuto := ctx.Bool("auto")

		if IsAuto {
			CurCon.GetInfo()
		} else {
			CurCon.SetQuery(ctx.String("input"))
			CurCon.Query()
		}
	}

	fmt.Println("All Task Done!!!!")
	return err
}
