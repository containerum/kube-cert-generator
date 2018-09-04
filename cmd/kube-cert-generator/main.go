package main

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"gopkg.in/urfave/cli.v2"
)

var (
	configFlag = cli.StringFlag{
		Name:    "config",
		Aliases: []string{"c"},
		Usage:   "path to config file",
		Value:   "config.toml",
	}
)

func main() {
	app := cli.App{
		Name: "kube-cert-generator",
		Flags: []cli.Flag{
			&configFlag,
		},
		Before: func(context *cli.Context) error {
			var cfg Config
			if _, err := toml.DecodeFile(context.String(configFlag.Name), &cfg); err != nil {
				return err
			}
			context.App.Metadata[configContextKey] = &cfg
			return nil
		},
		Commands: []*cli.Command{
			&generateCSRsCmd,
			&initCACmd,
			&signCommand,
		},
		Version: "1.0.1",
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}
