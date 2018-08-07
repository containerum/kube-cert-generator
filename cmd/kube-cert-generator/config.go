package main

import (
	"time"

	"github.com/containerum/kube-cert-generator/pkg/cert"
)

const configContextKey = "config"

func CertParamsFromConfig(cfg CertConfig) (cert.Params, error) {
	ret := cert.Params{
		ValidityPeriod: cfg.ValidityPeriod,
		KeySize:        cfg.KeySize,
	}

	return ret, nil
}

// CertConfig represents certificate creation configuration
type CertConfig struct {
	ValidityPeriod time.Duration `toml:"validity_period"`
	KeySize        int           `toml:"key_size"`
}

// ExtraCertConfig represents configuration for creating additional certs
type ExtraCertConfig struct {
	Name string `toml:"name"`

	cert.CommonFields
	CertConfig
	Hosts []cert.Host `toml:"hosts"`
}

// CAConfig represents configuration for certificate authority
type CAConfig struct {
	RootDir string `toml:"root_dir"`

	cert.CommonFields
	CertConfig
}

// Config represents app configuration
type Config struct {
	CommonFields   cert.CommonFields `toml:"common_fields"`
	OverwriteFiles bool              `toml:"overwrite_files"`
	CertConfig
	MasterNode  cert.Host         `toml:"master_node"`
	WorkerNodes cert.Hosts        `toml:"worker_nodes"`
	ExtraCerts  []ExtraCertConfig `toml:"extra_certs"`
	CAConfig    CAConfig          `toml:"ca_config"`
}
