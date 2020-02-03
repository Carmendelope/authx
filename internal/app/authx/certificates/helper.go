/*
 * Copyright 2019 Nalej
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package certificates

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/nalej/derrors"
	"github.com/nalej/grpc-authx-go"
	"github.com/rs/zerolog/log"
	"strings"
)

// CertHelper offers different operations to facilitate working with certificates.
type CertHelper struct {
	CACert     *x509.Certificate
	PrivateKey crypto.PrivateKey
}

type PEM struct {
	Certificate string
	PrivateKey  string
}

// NewCertHelper creates a new certificate helper
func NewCertHelper(caCertPath string, caPrivateKeyPath string) (*CertHelper, derrors.Error) {
	helper := &CertHelper{}
	lErr := helper.loadCACert(caCertPath, caPrivateKeyPath)
	if lErr != nil {
		return nil, lErr
	}
	return helper, nil
}

// loadCACert loads the CA certificate and private key in the helper for future operations.
func (ch *CertHelper) loadCACert(caCertPath string, caPrivateKeyPath string) derrors.Error {
	ca, err := tls.LoadX509KeyPair(caCertPath, caPrivateKeyPath)
	if err != nil {
		return derrors.AsError(err, "cannot load CA certificate an Private Key")
	}
	if len(ca.Certificate) == 0 {
		return derrors.NewNotFoundError("CA certificate not found in path")
	}
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return derrors.AsError(err, "cannot parse CA certificate")
	}
	ch.CACert = caCert
	ch.PrivateKey = ca.PrivateKey
	log.Info().Str("dnsNames", strings.Join(ch.CACert.DNSNames, ", ")).Msg("CA cert has been loaded")
	return nil
}

// SignCertificate creates a certificate based on the template
func (ch *CertHelper) SignCertificate(request *x509.Certificate) ([]byte, *rsa.PrivateKey, derrors.Error) {
	// create certificate keys
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, request, ch.CACert, pub, ch.PrivateKey)
	if err != nil {
		return nil, nil, derrors.AsError(err, "cannot sign certificate with CA")
	}
	return cert, priv, nil
}

func (ch *CertHelper) GetCaCertPEM() (string, derrors.Error) {
	out := &bytes.Buffer{}
	err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: ch.CACert.Raw})
	if err != nil {
		return "", derrors.AsError(err, "cannot transform CaCert to PEM")
	}
	return out.String(), nil
}

// GeneratePEM
func (ch *CertHelper) GeneratePEM(rawCert []byte, privateKey *rsa.PrivateKey) (*grpc_authx_go.PEMCertificate, derrors.Error) {
	// Export the content to PEM
	out := &bytes.Buffer{}
	err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: rawCert})
	if err != nil {
		return nil, derrors.AsError(err, "cannot transform certificate to PEM")
	}
	result := &grpc_authx_go.PEMCertificate{}
	result.Certificate = out.String()

	out.Reset()

	err = pem.Encode(out, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return nil, derrors.AsError(err, "cannot transform private key to PEM")
	}
	result.PrivateKey = out.String()
	return result, nil
}
