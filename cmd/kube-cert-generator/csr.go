package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"

	"github.com/containerum/kube-cert-generator/pkg/cert"
	"gopkg.in/urfave/cli.v2"
)

type csrParams struct {
	FileName    string
	CN          string
	O           string
	IncludeSANs bool
}

func (c csrParams) String() string {
	return fmt.Sprintf("File: %s, CN=%s, O=%s%s", c.FileName, c.CN, c.O, func() string {
		if c.IncludeSANs {
			return " with SANs"
		}
		return ""
	}())
}

var kubeStandardCSRs = []csrParams{
	{FileName: "admin", CN: "admin", O: "system:masters", IncludeSANs: false},
	{FileName: "kube-controller-manager", CN: "system:kube-controller-manager", O: "system:kube-controller-manager", IncludeSANs: false},
	{FileName: "kube-proxy", CN: "system:kube-proxy", O: "system:node-proxier", IncludeSANs: false},
	{FileName: "kubernetes", CN: "kubernetes", O: "kubernetes", IncludeSANs: true},
	{FileName: "kube-scheduler", CN: "system:kube-scheduler", O: "system:kube-scheduler", IncludeSANs: false},
	{FileName: "service-accounts", CN: "service-accounts", O: "Kubernetes", IncludeSANs: false},
}

func outputKeyCSR(fileName string, overwriteFiles bool, certParam cert.Params) error {
	key, err := certParam.GenKey()
	if err != nil {
		return err
	}
	keyFile, err := createFileIfNotExist(fileName+".key", overwriteFiles)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, certParam.CSRTemplate(), key)
	if err != nil {
		return err
	}
	csrFile, err := createFileIfNotExist(fileName+".csr", overwriteFiles)
	if err := pem.Encode(csrFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}); err != nil {
		return err
	}
	return nil
}

func generateCSRs(cfg *Config) error {
	fmt.Println("Generate pairs of private keys and certificate signing requests")

	fmt.Println("Generate basic kubernetes csr-key pairs")
	for _, param := range kubeStandardCSRs {
		fmt.Println(param)
		certParam, err := CertParamsFromConfig(cfg.CertConfig)
		if err != nil {
			return err
		}
		if param.IncludeSANs {
			certParam.SubjectAdditionalNames = cfg.MasterNode.ToSANs()
		}
		certParam.CommonFields = cfg.CommonFields
		certParam.Organization = []string{param.O}
		certParam.CommonName = param.CN

		if err := outputKeyCSR(param.FileName, cfg.OverwriteFiles, certParam); err != nil {
			return err
		}
	}

	fmt.Println("Generate node certificates")
	for _, node := range cfg.WorkerNodes {
		fmt.Printf("Node: %s, Addresses: %v\n", node.Alias, node.Addresses)
		certParam, err := CertParamsFromConfig(cfg.CertConfig)
		if err != nil {
			return err
		}
		certParam.SubjectAdditionalNames = node.ToSANs()
		certParam.CommonFields = cfg.CommonFields
		certParam.Organization = []string{fmt.Sprintf("system:node:%s", node.Alias)}
		certParam.CommonName = "system.nodes"

		if err := outputKeyCSR(node.Alias, cfg.OverwriteFiles, certParam); err != nil {
			return err
		}
	}

	fmt.Println("Generate extra certs")
	for _, extraCert := range cfg.ExtraCerts {
		certParam, err := CertParamsFromConfig(extraCert.CertConfig)
		if err != nil {
			return err
		}
		certParam.CommonFields = cfg.CommonFields

		str1, str2 := reflect.ValueOf(&certParam.CommonFields), reflect.ValueOf(&extraCert.CommonFields)
		for i := 0; i < str1.Elem().NumField(); i++ {
			if str2.Elem().Field(i).Len() > 0 {
				str1.Elem().Field(i).Set(str2.Elem().Field(i))
			}
		}

		fmt.Printf("%#v\n", certParam)

		if err := outputKeyCSR(extraCert.Name, cfg.OverwriteFiles, certParam); err != nil {
			return err
		}
	}

	return nil
}

var generateCSRsCmd = cli.Command{
	Name:  "gen-csr",
	Usage: "Generate private key and certificate signing requests using config",
	Action: func(ctx *cli.Context) error {
		return generateCSRs(ctx.App.Metadata[configContextKey].(*Config))
	},
}
