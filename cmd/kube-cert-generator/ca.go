package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/easypki/pkg/easypki"
	"github.com/google/easypki/pkg/store"
	"gopkg.in/urfave/cli.v2"
)

func initCA(cfg *Config, caName string) error {
	fmt.Println("Initialize certificate authority at", path.Join(cfg.CAConfig.RootDir, caName))
	caStore := getCAStore(cfg)

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

	certTemplate := certParams.CACertTemplate()
	cert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, privateKey.Public(), privateKey)
	if err != nil {
		return err
	}

	return caStore.Add(caName, caName, true, x509.MarshalPKCS1PrivateKey(privateKey), cert)
}

var caNameFlag = cli.StringFlag{
	Name:  "ca",
	Usage: "Certificate authority name",
	Value: "root",
}

var initCACmd = cli.Command{
	Name:  "init-ca",
	Usage: "initialize certificate authority",
	Flags: []cli.Flag{&caNameFlag},
	Action: func(ctx *cli.Context) error {
		return initCA(ctx.App.Metadata[configContextKey].(*Config), ctx.String(caNameFlag.Name))
	},
}

func getCAStore(cfg *Config) *store.Local {
	os.Mkdir(cfg.CAConfig.RootDir, os.ModePerm)
	return &store.Local{Root: cfg.CAConfig.RootDir}
}

func signCSRs(cfg *Config, files []string, caName string) error {
	pki := easypki.EasyPKI{Store: getCAStore(cfg)}
	caSigner, err := pki.GetCA(caName)
	if err != nil {
		return err
	}
	for _, file := range files {
		fmt.Println("Signing", file)
		content, err := ioutil.ReadFile(file)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(content)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return err
		}
		if err := csr.CheckSignature(); err != nil {
			return err
		}

		serial, err := rand.Int(rand.Reader, big.NewInt(big.MaxExp))
		if err != nil {
			return err
		}

		request := &easypki.Request{
			Name:                strings.TrimSuffix(path.Base(file), path.Ext(file)),
			IsClientCertificate: true,
			PrivateKeySize:      cfg.KeySize,
			Template: &x509.Certificate{
				Signature:          csr.Signature,
				SignatureAlgorithm: csr.SignatureAlgorithm,

				PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
				PublicKey:          csr.PublicKey,

				SerialNumber: serial,
				Issuer:       caSigner.Cert.Subject,
				Subject:      csr.Subject,
				NotBefore:    time.Now().UTC(),
				NotAfter:     time.Now().Add(cfg.ValidityPeriod.Duration).UTC(),
				KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		}

		if err := pki.Sign(caSigner, request); err != nil {
			return err
		}

		cert, err := pki.GetBundle(caName, request.Name)
		if err != nil {
			return err
		}

		certFile, err := createFileIfNotExist(cert.Name+".crt", cfg.OverwriteFiles)
		if err != nil {
			return err
		}

		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Cert.Raw}); err != nil {
			return err
		}
	}

	return nil
}

var signCommand = cli.Command{
	Name:  "sign",
	Usage: "Sign a certificate signing request",
	Flags: []cli.Flag{&caNameFlag},
	Action: func(ctx *cli.Context) error {
		return signCSRs(ctx.App.Metadata[configContextKey].(*Config), ctx.Args().Tail(), ctx.String(caNameFlag.Name))
	},
}
