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

var caNameFlag = cli.StringFlag{
	Name:  "name",
	Usage: "Certificate authority name",
	Value: "root",
}

var initCACmd = cli.Command{
	Name:  "init-ca",
	Usage: "initialize certificate authority",
	Flags: []cli.Flag{
		&caNameFlag,
		&configFlag,
		// &outputDirFlag,
	},
	Before: func(ctx *cli.Context) error {
		if err := initConfig(ctx); err != nil {
			return err
		}
		if err := initOutputDir(ctx); err != nil {
			return err
		}
		return nil
	},
	Action: func(ctx *cli.Context) error {
		return initCA(ctx.App.Metadata[configContextKey].(*Config), ctx.String(caNameFlag.Name), ctx.App.Metadata[outputDirContextKey].(string))
	},
}

var signCommand = cli.Command{
	Name:  "sign",
	Usage: "Sign a certificate signing request",
	Flags: []cli.Flag{
		&caNameFlag,
		&configFlag,
		&outputDirFlag,
	},
	Before: func(ctx *cli.Context) error {
		if err := initConfig(ctx); err != nil {
			return err
		}
		if err := initOutputDir(ctx); err != nil {
			return err
		}
		return nil
	},
	Action: func(ctx *cli.Context) error {
		return signCSRs(ctx.App.Metadata[configContextKey].(*Config), ctx.Args().Slice(), ctx.String(caNameFlag.Name), ctx.App.Metadata[outputDirContextKey].(string))
	},
}

func initCA(cfg *Config, caName string, outputDir string) error {
	fmt.Println("Initialize certificate authority at", path.Join(outputDir, cfg.CAConfig.RootDir, caName))
	caStore := getCAStore(cfg, outputDir)

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

func getCAStore(cfg *Config, outputDir string) *store.Local {
	os.Mkdir(path.Join(outputDir, cfg.CAConfig.RootDir), os.ModePerm)
	return &store.Local{Root: path.Join(outputDir, cfg.CAConfig.RootDir)}
}

func signCSRs(cfg *Config, files []string, caName string, outputDir string) error {
	pki := easypki.EasyPKI{Store: getCAStore(cfg, "")}
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

		// step: create the request template
		template := x509.Certificate{
			SerialNumber:          serial,
			Issuer:                caSigner.Cert.Subject,
			Subject:               csr.Subject,
			NotBefore:             time.Now().UTC(),
			NotAfter:              time.Now().Add(cfg.ValidityPeriod.Duration).UTC(),
			BasicConstraintsValid: true,
			IsCA:        true,
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IPAddresses: csr.IPAddresses,
			DNSNames:    csr.DNSNames,
		}

		// step: sign the certificate authority
		cert, err := x509.CreateCertificate(rand.Reader, &template, caSigner.Cert, csr.PublicKey, caSigner.Key)
		if err != nil {
			return fmt.Errorf("failed to generate certificate, error: %s", err)
		}

		certName := path.Join(outputDir, strings.TrimSuffix(path.Base(file), path.Ext(file))+".crt")
		certFile, err := createFileIfNotExist(certName, cfg.OverwriteFiles)
		if err != nil {
			return err
		}
		fmt.Printf("Cert created: %v\n", certName)

		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return err
		}
	}

	return nil
}
