/*
 * Copyright 2020 Nalej
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
 */

package certificates_monitoring

import (
	"github.com/google/uuid"
	"github.com/nalej/authx/internal/app/authx/entities"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"time"
)

func CertificatesMonitoringTests(provider CertificatesMonitoring) {
	ginkgo.Context("Having a Certificates Monitoring Provider", func() {
		ginkgo.AfterEach(func() {
			// Clean after each test
			gomega.Expect(provider.Truncate()).To(gomega.Succeed())
		})
		// ADD
		ginkgo.It("can add a new certificate to the model", func() {
			newCertificate := &entities.MonitoringCertificate{
				OrganizationId:      uuid.New().String(),
				CertificateId:       uuid.New().String(),
				CreationTimestamp:   time.Now().UnixNano(),
				ExpirationTimestamp: 0,
				RevocationTimestamp: 0,
			}
			gomega.Expect(provider.Add(newCertificate)).To(gomega.Succeed())
		})
		ginkgo.It("should fail if adding the same certificate twice (organizationId and certificateId)", func() {
			newCertificate := &entities.MonitoringCertificate{
				OrganizationId:      uuid.New().String(),
				CertificateId:       uuid.New().String(),
				CreationTimestamp:   time.Now().UnixNano(),
				ExpirationTimestamp: 0,
				RevocationTimestamp: 0,
			}
			gomega.Expect(provider.Add(newCertificate)).To(gomega.Succeed())
			gomega.Expect(provider.Add(newCertificate)).ToNot(gomega.Succeed())
		})

		// GET
		ginkgo.It("can retrieve an existing certificate", func() {
			addedCertificate := &entities.MonitoringCertificate{
				OrganizationId:      uuid.New().String(),
				CertificateId:       uuid.New().String(),
				CreationTimestamp:   time.Now().UnixNano(),
				ExpirationTimestamp: 0,
				RevocationTimestamp: 0,
			}
			gomega.Expect(provider.Add(addedCertificate)).To(gomega.Succeed())

			certificate, err := provider.Get(addedCertificate.OrganizationId, addedCertificate.CertificateId)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(certificate).To(gomega.Equal(addedCertificate))
		})
		ginkgo.It("should fail when retrieving an inexistent certificate", func() {
			_, err := provider.Get(uuid.New().String(), uuid.New().String())
			gomega.Expect(err).ToNot(gomega.Succeed())
		})

		// LIST
		ginkgo.It("can list all the monitoring certificates of an organization", func() {
			organizationId := uuid.New().String()
			now := time.Now().UnixNano()
			certNum := 10
			addedCertificates := make([]*entities.MonitoringCertificate, 0, certNum)
			for i := 0; i < certNum; i++ {
				newCertificate := entities.MonitoringCertificate{
					OrganizationId:      organizationId,
					CertificateId:       uuid.New().String(),
					CreationTimestamp:   now,
					ExpirationTimestamp: 0,
					RevocationTimestamp: 0,
				}
				addedCertificates = append(addedCertificates, &newCertificate)
				gomega.Expect(provider.Add(&newCertificate)).To(gomega.Succeed())
			}
			// Control certificates
			for i := 0; i < certNum; i++ {
				newCertificate := entities.MonitoringCertificate{
					OrganizationId:      uuid.New().String(),
					CertificateId:       uuid.New().String(),
					CreationTimestamp:   now,
					ExpirationTimestamp: 0,
					RevocationTimestamp: 0,
				}
				gomega.Expect(provider.Add(&newCertificate)).To(gomega.Succeed())
			}

			list, err := provider.List(organizationId)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(list).To(gomega.ConsistOf(addedCertificates))
		})
		ginkgo.It("returns an empty list if there's no certificates for that organization when listing", func() {
			// Control certificates
			for i := 0; i < 10; i++ {
				newCertificate := entities.MonitoringCertificate{
					OrganizationId:      uuid.New().String(),
					CertificateId:       uuid.New().String(),
					CreationTimestamp:   time.Now().UnixNano(),
					ExpirationTimestamp: 0,
					RevocationTimestamp: 0,
				}
				gomega.Expect(provider.Add(&newCertificate)).To(gomega.Succeed())
			}

			list, err := provider.List(uuid.New().String())
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(list).To(gomega.BeEmpty())
		})

		// REVOKE
		ginkgo.It("can revoke a certificate", func() {
			addedCertificate := &entities.MonitoringCertificate{
				OrganizationId:      uuid.New().String(),
				CertificateId:       uuid.New().String(),
				CreationTimestamp:   time.Now().UnixNano(),
				ExpirationTimestamp: 0,
				RevocationTimestamp: 0,
			}
			gomega.Expect(provider.Add(addedCertificate)).To(gomega.Succeed())

			addedCertificate.RevocationTimestamp = time.Now().UnixNano()
			gomega.Expect(provider.Update(addedCertificate)).
				To(gomega.Succeed())

			revokedCertificate, err := provider.Get(addedCertificate.OrganizationId, addedCertificate.CertificateId)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(revokedCertificate.RevocationTimestamp).ToNot(gomega.Equal(0))
		})
		ginkgo.It("fails when revoking an unexistent certificate", func() {
			addedCertificate := &entities.MonitoringCertificate{
				OrganizationId:      uuid.New().String(),
				CertificateId:       uuid.New().String(),
				CreationTimestamp:   time.Now().UnixNano(),
				ExpirationTimestamp: 0,
				RevocationTimestamp: 0,
			}
			gomega.Expect(provider.Add(addedCertificate)).To(gomega.Succeed())

			wrongOrgCertificate := &entities.MonitoringCertificate{
				OrganizationId: uuid.New().String(),
				CertificateId:  addedCertificate.CertificateId,
			}
			gomega.Expect(provider.Update(wrongOrgCertificate)).ToNot(gomega.Succeed())
			wrongIdCertificate := &entities.MonitoringCertificate{
				OrganizationId: addedCertificate.OrganizationId,
				CertificateId:  uuid.New().String(),
			}
			gomega.Expect(provider.Update(wrongIdCertificate)).
				ToNot(gomega.Succeed())
		})

		// TRUNCATE
		ginkgo.It("can clean the model", func() {
			organizationId := uuid.New().String()
			for i := 0; i < 10; i++ {
				newCertificate := entities.MonitoringCertificate{
					OrganizationId:      organizationId,
					CertificateId:       uuid.New().String(),
					CreationTimestamp:   time.Now().UnixNano(),
					ExpirationTimestamp: 0,
					RevocationTimestamp: 0,
				}
				gomega.Expect(provider.Add(&newCertificate)).To(gomega.Succeed())
			}

			gomega.Expect(provider.Truncate()).To(gomega.Succeed())
			list, err := provider.List(organizationId)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(list).To(gomega.BeEmpty())
		})
	})
}
