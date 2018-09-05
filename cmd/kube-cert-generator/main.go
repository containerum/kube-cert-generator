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
	outputDirFlag = cli.StringFlag{
		Name:    "output",
		Aliases: []string{"o"},
		Usage:   "path to output dir",
		Value:   "cert",
	}
	inputDirFlag = cli.StringFlag{
		Name:    "input",
		Aliases: []string{"o"},
		Usage:   "path to input dir",
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
		Version: "1.0.4",
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

func initConfig(ctx *cli.Context) error {
	var cfg Config
	if _, err := toml.DecodeFile(ctx.String(configFlag.Name), &cfg); err != nil {
		return err
	}
	ctx.App.Metadata[configContextKey] = &cfg
	return nil
}

func initOutputDir(ctx *cli.Context) error {
	ctx.App.Metadata[outputDirContextKey] = ctx.String("output")
	if outDir := ctx.App.Metadata[outputDirContextKey].(string); outDir != "" {
		if err := createDirIfNotExists(outDir); err != nil {
			return err
		}
	}
	return nil
}
