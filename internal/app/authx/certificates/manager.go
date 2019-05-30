/*
* Copyright (C) 2019 Nalej - All Rights Reserved
*/

package certificates

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/nalej/authx/internal/app/authx/config"
	"github.com/nalej/derrors"
	"github.com/nalej/grpc-authx-go"
	"math/big"
	"math/rand"
	"time"
)

// CertValidity of 2 years as default.
const CertValidity = time.Hour * 24 * 365 * 2

type Manager struct{
	config config.Config
	helper * CertHelper
}

func NewManager(config config.Config, certHelper * CertHelper) Manager{
	return Manager{
		config: config,
		helper: certHelper,
	}
}

// certFromEdgeControllerRequest creates a x509 certificate with the information of the request.
func (m * Manager) certFromEdgeControllerRequest(request *grpc_authx_go.EdgeControllerCertRequest) *x509.Certificate{
	x509 := &x509.Certificate{
		// TODO Use another serial number generator
		SerialNumber:                big.NewInt(rand.Int63()),
		Issuer:                      m.helper.CACert.Issuer,
		Subject:                     pkix.Name{
			Organization: []string{request.OrganizationId},
			OrganizationalUnit: []string{request.EdgeControllerId},
			CommonName:         request.Name,
		},
		NotBefore:                   time.Now(),
		NotAfter:                    time.Now().Add(CertValidity),
		KeyUsage:                    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                        false,
		MaxPathLen:                  0,
		MaxPathLenZero:              false,
		IssuingCertificateURL:       m.helper.CACert.DNSNames,
	}
	return x509
}

// CreateControllerCert creates a certificate for an edge controller.
func (m * Manager) CreateControllerCert(request *grpc_authx_go.EdgeControllerCertRequest) (*grpc_authx_go.PEMCertificate, derrors.Error) {
	toSign := m.certFromEdgeControllerRequest(request)
	cert, pk, err := m.helper.SignCertificate(toSign)
	if err != nil{
		return nil, err
	}
	pem, err := m.helper.GeneratePEM(cert, pk)
	if err != nil{
		return nil, err
	}
	return pem, nil
}
