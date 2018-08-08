// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package easypki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

func defaultTemplate(genReq *Request, publicKey crypto.PublicKey) error {
	publicKeyBytes, err := asn1.Marshal(*publicKey.(*rsa.PublicKey))
	if err != nil {
		return fmt.Errorf("failed marshaling public key: %v", err)
	}
	subjectKeyID := sha1.Sum(publicKeyBytes)
	genReq.Template.SubjectKeyId = subjectKeyID[:]

	// Random serial number.
	snLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err := rand.Int(rand.Reader, snLimit)
	if err != nil {
		return fmt.Errorf("failed generating serial number: %s", err)
	}
	genReq.Template.SerialNumber = sn

	genReq.Template.NotBefore = time.Now()
	genReq.Template.SignatureAlgorithm = x509.SHA256WithRSA
	return nil
}

func caTemplate(genReq *Request, intermediateCA bool) error {
	genReq.Template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	genReq.Template.BasicConstraintsValid = true
	genReq.Template.MaxPathLenZero = true

	if intermediateCA {
		return nil
	}

	// Root certificate can self-sign.
	genReq.Template.Issuer = genReq.Template.Subject
	genReq.Template.AuthorityKeyId = genReq.Template.SubjectKeyId
	return nil
}

func nonCATemplate(genReq *Request) {
	if !genReq.IsClientCertificate {
		genReq.Template.ExtKeyUsage = append(genReq.Template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	// Clients can only use ClientAuth
	genReq.Template.ExtKeyUsage = append(genReq.Template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)

	// set the usage for non-CA certificates
	genReq.Template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
}
