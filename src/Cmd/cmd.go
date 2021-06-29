package Cmd

import (
	"Zombie/src/Moudle"
	"github.com/urfave/cli/v2"
)

var Brute = cli.Command{
	Name:    "Brute",
	Action:  Moudle.Brute,
	Aliases: []string{"B"},
	Flags: []cli.Flag{
		StringFlag("username", "u", "", ""),
		StringFlag("password", "p", "", ""),
		StringFlag("userdict", "U", "", ""),
		StringFlag("passdict", "P", "", ""),
		StringFlag("uppair", "UP", "", ""),
		SimpleStringFlag("ip", "", ""),
		SimpleStringFlag("IP", "", ""),
		StringFlag("file", "f", "./res.log", ""),
		StringFlag("server", "s", "", ""),
		BoolSimpleFlag("ssl", false, ""),
		IntSimpleFlag("timeout", 2, ""),
		IntFlag("thread", "t", "", 60),
		BoolFlag("simple", "e", false, ""),
		IntSimpleFlag("proc", 0, ""),
	},
}

var Query = cli.Command{
	Name:    "Query",
	Action:  Moudle.Exec,
	Aliases: []string{"Q"},
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "username",
			Aliases: []string{"u"},
			Value:   "",
			Usage:   "",
		},
		&cli.StringFlag{
			Name:    "password",
			Aliases: []string{"p"},
			Value:   "",
			Usage:   "",
		},
		&cli.StringFlag{
			Name:  "ip",
			Value: "",
			Usage: "",
		},
		&cli.StringFlag{
			Name:    "input",
			Aliases: []string{"i"},
			Value:   "",
			Usage:   "",
		},
		StringFlag("InputFile", "F", "", ""),
		StringFlag("server", "s", "", ""),
		BoolFlag("auto", "a", false, ""),
	},
}

var Decrypt = cli.Command{
	Name:    "Decrypt",
	Aliases: []string{"D"},
	Subcommands: []*cli.Command{
		{
			Name:    "all",
			Usage:   "",
			Aliases: []string{"a"},
			Action:  Moudle.DecryptAll,
		},
		{
			Name:    "Navicat",
			Aliases: []string{"N"},
			Action:  Moudle.DeNavicat,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "cipher",
					Aliases: []string{"c"},
					Value:   "",
					Usage:   "",
				},
			},
		},
		{
			Name:    "Xshell",
			Aliases: []string{"x"},
			Action:  Moudle.DeXshell,
		},
	},
}

func StringFlag(name, alases, value, usage string) *cli.StringFlag {
	return &cli.StringFlag{
		Name:    name,
		Aliases: []string{alases},
		Value:   value,
		Usage:   usage,
	}
}

func SimpleStringFlag(name, value, usage string) *cli.StringFlag {
	return &cli.StringFlag{
		Name:  name,
		Value: value,
		Usage: usage,
	}
}

func BoolSimpleFlag(name string, value bool, usage string) *cli.BoolFlag {
	return &cli.BoolFlag{
		Name:  name,
		Value: value,
		Usage: usage,
	}
}

func BoolFlag(name, alases string, value bool, usage string) *cli.BoolFlag {
	return &cli.BoolFlag{
		Name:    name,
		Aliases: []string{alases},
		Value:   value,
		Usage:   usage,
	}
}

func IntSimpleFlag(name string, value int, usage string) *cli.IntFlag {
	return &cli.IntFlag{
		Name:  name,
		Value: value,
		Usage: usage,
	}
}

func IntFlag(name, alases, usage string, value int) *cli.IntFlag {
	return &cli.IntFlag{
		Name:    name,
		Aliases: []string{alases},
		Value:   value,
		Usage:   usage,
	}
}
