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
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/google/uuid"
	"github.com/nalej/authx/internal/app/authx/config"
	"github.com/nalej/authx/internal/app/authx/entities"
	"github.com/nalej/authx/internal/app/authx/providers/certificates_monitoring"
	"github.com/nalej/derrors"
	"github.com/nalej/grpc-authx-go"
	"github.com/nalej/grpc-common-go"
	"math/big"
	"math/rand"
	"net"
	"time"
)

// CertValidity of 2 years as default.
const CertValidity = time.Hour * 24 * 365 * 2

type Manager struct {
	config   config.Config
	helper   *CertHelper
	provider certificates_monitoring.CertificatesMonitoring
}

func NewManager(config config.Config, certHelper *CertHelper, provider certificates_monitoring.CertificatesMonitoring) Manager {
	return Manager{
		config:   config,
		helper:   certHelper,
		provider: provider,
	}
}

// certFromEdgeControllerRequest creates a x509 certificate with the information of the request.
func (m *Manager) certFromEdgeControllerRequest(request *grpc_authx_go.EdgeControllerCertRequest) *x509.Certificate {
	ipAddresses := make([]net.IP, 0)
	for _, ip := range request.Ips {
		ipAddresses = append(ipAddresses, net.ParseIP(ip))
	}
	return &x509.Certificate{
		// TODO Use another serial number generator
		SerialNumber: big.NewInt(rand.Int63()),
		Issuer:       m.helper.CACert.Issuer,
		Subject: pkix.Name{
			Organization:       []string{request.OrganizationId},
			OrganizationalUnit: []string{request.EdgeControllerId},
			CommonName:         request.Name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(CertValidity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
		IssuingCertificateURL: m.helper.CACert.DNSNames,
		IPAddresses:           ipAddresses,
	}
}

// CreateControllerCert creates a certificate for an edge controller.
func (m *Manager) CreateControllerCert(request *grpc_authx_go.EdgeControllerCertRequest) (*grpc_authx_go.PEMCertificate, derrors.Error) {
	toSign := m.certFromEdgeControllerRequest(request)
	cert, pk, err := m.helper.SignCertificate(toSign)
	if err != nil {
		return nil, err
	}
	pem, err := m.helper.GeneratePEM(cert, pk)
	if err != nil {
		return nil, err
	}
	return pem, nil
}

// certFromEdgeControllerRequest creates a x509 certificate with the information of the request.
func (m *Manager) newMonitoringClientCertificate(request *grpc_authx_go.CreateMonitoringClientCertificateRequest, certificateId string) *x509.Certificate {
	return &x509.Certificate{
		// TODO Use another serial number generator
		SerialNumber: big.NewInt(rand.Int63()),
		Issuer:       m.helper.CACert.Issuer,
		Subject: pkix.Name{
			Organization:       []string{request.OrganizationId},
			OrganizationalUnit: []string{certificateId},
			CommonName:         certificateId,
			SerialNumber:       certificateId,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(CertValidity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
		IssuingCertificateURL: m.helper.CACert.DNSNames,
	}
}

// CreateMonitoringClientCertificate creates a new certificate for the monitoring endpoint for the given organization.
func (m *Manager) CreateMonitoringClientCertificate(request *grpc_authx_go.CreateMonitoringClientCertificateRequest) (*grpc_authx_go.CreateMonitoringClientCertificateResponse, derrors.Error) {
	certificateId := uuid.New().String()
	certificatex509 := m.newMonitoringClientCertificate(request, certificateId)
	cert, privateKey, err := m.helper.SignCertificate(certificatex509)
	if err != nil {
		return nil, err
	}

	clientCertificatePEM, err := m.helper.GeneratePEM(cert, privateKey)
	if err != nil {
		return nil, err
	}

	monitoringCertificate := &entities.MonitoringCertificate{
		OrganizationId:      request.OrganizationId,
		CertificateId:       certificateId,
		CreationTimestamp:   certificatex509.NotBefore.UnixNano(),
		ExpirationTimestamp: certificatex509.NotAfter.UnixNano(),
	}
	err = m.provider.Add(monitoringCertificate)
	if err != nil {
		return nil, err
	}

	return &grpc_authx_go.CreateMonitoringClientCertificateResponse{
		OrganizationId:    request.OrganizationId,
		CertificateId:     certificateId,
		ExpirationTime:    certificatex509.NotAfter.UnixNano(),
		ClientCertificate: clientCertificatePEM,
		CaCertificate:     "a", //m.helper.CACert.PublicKey, // TODO what to put here exactly and why?
	}, nil
}

// ListMonitoringClientCertificates lists all the monitoring certificates of the given organization.
func (m *Manager) ListMonitoringClientCertificates(request *grpc_authx_go.ListMonitoringClientCertificateRequest) (*grpc_authx_go.ListMonitoringClientCertificateResponse, derrors.Error) {
	list, err := m.provider.List(request.OrganizationId)
	if err != nil {
		return nil, err
	}
	responseList := make([]*grpc_authx_go.MonitoringClientCertificate, len(list))
	for i, certificate := range list {
		responseList[i] = certificate.ToGRPC()
	}
	return &grpc_authx_go.ListMonitoringClientCertificateResponse{
		OrganizationId: request.OrganizationId,
		Certificates:   responseList,
	}, nil
}

// ValidateMonitoringCertificate checks if the given certificate is still valid.
func (m *Manager) ValidateMonitoringCertificate(request *grpc_authx_go.ValidateMonitoringClientCertificateRequest) (*grpc_common_go.Success, derrors.Error) {
	now := time.Now().UnixNano()
	certificate, err := m.provider.Get(request.OrganizationId, request.CertificateId)
	if err != nil {
		return nil, err
	}
	switch {
	case certificate.ExpirationTimestamp < now:
		return nil, derrors.NewGenericError("certificate has expired")
	case certificate.RevocationTimestamp > 0 && certificate.RevocationTimestamp <= now:
		return nil, derrors.NewGenericError("Certificate has been revoked")
	}
	return &grpc_common_go.Success{}, nil
}

// RevokeMonitoringCertificate revokes the given certificate.
func (m *Manager) RevokeMonitoringCertificate(request *grpc_authx_go.RevokeMonitoringClientCertificateRequest) (*grpc_common_go.Success, derrors.Error) {
	certificate, err := m.provider.Get(request.OrganizationId, request.CertificateId)
	if err != nil {
		return nil, err
	}
	certificate.RevocationTimestamp = time.Now().UnixNano()
	err = m.provider.Update(certificate)
	if err != nil {
		return nil, err
	}
	return &grpc_common_go.Success{}, nil
}
