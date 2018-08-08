package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path"

	"github.com/google/easypki/pkg/store"
	"gopkg.in/urfave/cli.v2"
)

func initCA(cfg *Config) error {
	fmt.Println("Initialize certificate authority at", cfg.CAConfig.RootDir)
	if err := store.InitCADir(cfg.CAConfig.RootDir); err != nil {
		return err
	}

	fmt.Println("Generate key/cert")
	certParams, err := CertParamsFromConfig(cfg.CertConfig)
	if err != nil {
		return err
	}
	certParams.CommonFields = cfg.CAConfig.CommonFields

	privateKey, err := certParams.GenKey()
	if err != nil {
		return err
	}

	privateKeyFile, err := createFileIfNotExist(path.Join(cfg.CAConfig.RootDir, "keys", "ca.key"), cfg.OverwriteFiles)
	if err != nil {
		return err
	}
	if err := pem.Encode(privateKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return err
	}

	certTemplate := certParams.CACertTemplate()

	cert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, privateKey.Public(), privateKey)
	if err != nil {
		return err
	}
	certFile, err := createFileIfNotExist(path.Join(cfg.CAConfig.RootDir, "certs", "ca.crt"), cfg.OverwriteFiles)
	if err != nil {
		return err
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return err
	}

	return nil
}

var initCACmd = cli.Command{
	Name:  "init-ca",
	Usage: "initialize certificate authority",
	Action: func(ctx *cli.Context) error {
		return initCA(ctx.App.Metadata[configContextKey].(*Config))
	},
}
