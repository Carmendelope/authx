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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/nalej/authx/internal/app/authx/config"
	"github.com/nalej/authx/internal/app/authx/providers/certificates_monitoring"
	"github.com/nalej/grpc-authx-go"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/rs/zerolog/log"
	"math/big"
	"time"
)

func createTestCA() (*x509.Certificate, *rsa.PrivateKey) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	gomega.Expect(err).To(gomega.Succeed())

	caCert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Issuer: pkix.Name{
			Organization: []string{"Nalej"},
		},
		Subject: pkix.Name{
			Organization: []string{"Nalej"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(CertValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		DNSNames:              []string{"*.fake.nalej.tech"},
	}
	publicKey := &privateKey.PublicKey
	rawCert, err := x509.CreateCertificate(rand.Reader, &caCert, &caCert, publicKey, privateKey)
	gomega.Expect(err).To(gomega.Succeed())

	cert, err := x509.ParseCertificate(rawCert)
	gomega.Expect(err).To(gomega.Succeed())

	return cert, privateKey
}

var certificatesProvider = certificates_monitoring.NewCertificatesMonitoringMockup()
var testManager Manager

var _ = ginkgo.Describe("The certificates manager", func() {
	ginkgo.BeforeSuite(func() {
		testCA, testPK := createTestCA()
		helper := &CertHelper{
			CACert:     testCA,
			PrivateKey: testPK,
		}

		emptyCfg := config.Config{}

		testManager = NewManager(emptyCfg, helper, certificatesProvider)
	})

	ginkgo.AfterEach(func() {
		// Clean model after each test
		gomega.Expect(certificatesProvider.Truncate()).To(gomega.Succeed())
	})

	ginkgo.It("should be able to generate an edge controller certificate", func() {
		request := &grpc_authx_go.EdgeControllerCertRequest{
			OrganizationId:   "organization_id",
			EdgeControllerId: "edge_controller_id",
			Name:             "Fake EC",
			Ips:              []string{"10.0.0.10", "192.168.250.10"},
		}
		ecCert, err := testManager.CreateControllerCert(request)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(ecCert).ToNot(gomega.BeNil())
		gomega.Expect(ecCert.Certificate).ShouldNot(gomega.BeNil())
		gomega.Expect(ecCert.PrivateKey).ShouldNot(gomega.BeNil())

		x509Cert, cErr := tls.X509KeyPair([]byte(ecCert.Certificate), []byte(ecCert.PrivateKey))
		gomega.Expect(cErr).To(gomega.Succeed())

		block, _ := pem.Decode([]byte(ecCert.Certificate))
		gomega.Expect(block).ShouldNot(gomega.BeNil())

		cert, perr := x509.ParseCertificate(block.Bytes)
		gomega.Expect(perr).To(gomega.Succeed())

		log.Info().Interface("cert", x509Cert).Msg("result")
		log.Info().Interface("cert", cert).Msg("result")
	})

	ginkgo.It("should be able to create a monitoring certificate", func() {
		request := &grpc_authx_go.CreateMonitoringClientCertificateRequest{
			OrganizationId: "organization_id",
		}

		response, err := testManager.CreateMonitoringClientCertificate(request)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(response.ClientCertificate).ToNot(gomega.BeNil())
		gomega.Expect(response.CaCertificate).ToNot(gomega.BeEmpty())

		monitoringCertificate := response.ClientCertificate

		x509Cert, cErr := tls.X509KeyPair([]byte(monitoringCertificate.Certificate), []byte(monitoringCertificate.PrivateKey))
		gomega.Expect(cErr).To(gomega.Succeed())

		block, _ := pem.Decode([]byte(monitoringCertificate.Certificate))
		gomega.Expect(block).ShouldNot(gomega.BeNil())

		cert, perr := x509.ParseCertificate(block.Bytes)
		gomega.Expect(perr).To(gomega.Succeed())

		log.Info().Interface("cert", x509Cert).Msg("result")
		log.Info().Interface("cert", cert).Msg("result")
	})

	ginkgo.It("should be able to list monitoring certificates that belongs to an organization", func() {
		creationRequest := &grpc_authx_go.CreateMonitoringClientCertificateRequest{
			OrganizationId: "organization_id",
		}
		certNum := 10
		creationResponseList := make([]*grpc_authx_go.CreateMonitoringClientCertificateResponse, certNum)
		for i := 0; i < certNum; i++ {
			response, err := testManager.CreateMonitoringClientCertificate(creationRequest)
			gomega.Expect(err).To(gomega.Succeed())
			creationResponseList[i] = response
		}

		listRequest := &grpc_authx_go.ListMonitoringClientCertificateRequest{
			OrganizationId: creationRequest.OrganizationId,
		}
		listResponse, err := testManager.ListMonitoringClientCertificates(listRequest)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(listResponse.OrganizationId).To(gomega.Equal(creationRequest.OrganizationId))
		gomega.Expect(listResponse.Certificates).To(gomega.HaveLen(certNum))
		for _, listedCertificate := range listResponse.Certificates {
			found := false
			for _, created := range creationResponseList {
				if created.CertificateId == listedCertificate.CertificateId {
					found = true
				}
			}
			gomega.Expect(found).To(gomega.BeTrue())
		}
	})

	ginkgo.It("must be able to revoke monitoring certificates", func() {
		creationRequest := &grpc_authx_go.CreateMonitoringClientCertificateRequest{
			OrganizationId: "organization_id",
		}
		creationResponse, err := testManager.CreateMonitoringClientCertificate(creationRequest)
		gomega.Expect(err).To(gomega.Succeed())

		revocationRequest := &grpc_authx_go.RevokeMonitoringClientCertificateRequest{
			OrganizationId: creationRequest.OrganizationId,
			CertificateId:  creationResponse.CertificateId,
		}
		_, err = testManager.RevokeMonitoringCertificate(revocationRequest)
		gomega.Expect(err).To(gomega.Succeed())

		listRequest := &grpc_authx_go.ListMonitoringClientCertificateRequest{
			OrganizationId: creationRequest.OrganizationId,
		}
		listResponse, err := testManager.ListMonitoringClientCertificates(listRequest)
		gomega.Expect(err).To(gomega.Succeed())
		now := time.Now().UnixNano()
		for _, certificate := range listResponse.Certificates {
			gomega.Expect(certificate.RevocationTime < now).To(gomega.BeTrue())
		}
	})

	ginkgo.It("should be able to validate a certificate correctly", func() {
		creationRequest := &grpc_authx_go.CreateMonitoringClientCertificateRequest{
			OrganizationId: "organization_id",
		}
		creationResponse, err := testManager.CreateMonitoringClientCertificate(creationRequest)
		gomega.Expect(err).To(gomega.Succeed())

		validationRequest := &grpc_authx_go.ValidateMonitoringClientCertificateRequest{
			OrganizationId: creationRequest.OrganizationId,
			CertificateId:  creationResponse.CertificateId,
		}
		_, err = testManager.ValidateMonitoringCertificate(validationRequest)
		gomega.Expect(err).To(gomega.Succeed())

		revocationRequest := &grpc_authx_go.RevokeMonitoringClientCertificateRequest{
			OrganizationId: creationRequest.OrganizationId,
			CertificateId:  creationResponse.CertificateId,
		}
		_, err = testManager.RevokeMonitoringCertificate(revocationRequest)
		gomega.Expect(err).To(gomega.Succeed())

		_, err = testManager.ValidateMonitoringCertificate(validationRequest)
		gomega.Expect(err).To(gomega.HaveOccurred())
	})
})
