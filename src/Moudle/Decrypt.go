package Moudle

import (
	"Zombie/src/Utils"
	"Zombie/src/ZbCrypto"
	"fmt"
	"github.com/urfave/cli/v2"
)

func DecryptAll(ctx *cli.Context) (err error) {

	return err
}

func DeXshell(ctx *cli.Context) (err error) {

	return err
}

func DeNavicat(ctx *cli.Context) (err error) {
	if ctx.IsSet("cipher") {
		plaintext, err := ZbCrypto.DeNavicat(ctx.String("cipher"))
		if err != nil {
			return err
		}
		fmt.Println("Decrypt result is : " + plaintext)
	}

	InfoList := Utils.ReadNavicatReg()

	for _, info := range InfoList {
		fmt.Println(info)
	}

	return err
}
