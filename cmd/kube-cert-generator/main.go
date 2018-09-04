package main

import (
	"fmt"
	"os"

	"gopkg.in/urfave/cli.v2"
)

var (
	configFlag = cli.StringFlag{
		Name:    "config",
		Aliases: []string{"c"},
		Usage:   "path to config file",
		Value:   "config.toml",
	}
	outputDirFlag = cli.StringFlag{
		Name:    "output",
		Aliases: []string{"o"},
		Usage:   "path to output dir",
		Value:   "cert",
	}
)

func main() {
	app := cli.App{
		Name: "kube-cert-generator",
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
