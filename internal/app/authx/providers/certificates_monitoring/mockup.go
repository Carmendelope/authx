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
	"github.com/nalej/authx/internal/app/authx/entities"
	"github.com/nalej/derrors"
	"sync"
	"time"
)

type CertificatesMonitoringMockup struct {
	sync.Mutex
	data map[string]map[string]entities.MonitoringCertificate
}

func NewCertificatesMonitoringMockup() *CertificatesMonitoringMockup {
	return &CertificatesMonitoringMockup{
		data: make(map[string]map[string]entities.MonitoringCertificate, 0),
	}
}

func (db *CertificatesMonitoringMockup) Add(certificate *entities.MonitoringCertificate) derrors.Error {
	certificates, exists := db.data[certificate.OrganizationId]
	if !exists {
		certificates = make(map[string]entities.MonitoringCertificate)
		db.data[certificate.OrganizationId] = certificates
	}
	_, exists = certificates[certificate.CertificateId]
	if exists {
		return derrors.NewAlreadyExistsError("the certificate already exists")
	}
	certificates[certificate.CertificateId] = *certificate
	return nil
}

func (db *CertificatesMonitoringMockup) Get(organizationId string, certificateId string) (*entities.MonitoringCertificate, derrors.Error) {
	certificates, exists := db.data[organizationId]
	if !exists {
		return nil, derrors.NewNotFoundError("the organization does not have certificates")
	}
	certificate, exists := certificates[certificateId]
	if !exists {
		return nil, derrors.NewNotFoundError("the certificate does not exists")
	}
	return &certificate, nil
}

func (db *CertificatesMonitoringMockup) List(organizationId string) ([]*entities.MonitoringCertificate, derrors.Error) {
	certificates, exists := db.data[organizationId]
	if !exists {
		return make([]*entities.MonitoringCertificate, 0, len(certificates)), nil
	}
	list := make([]*entities.MonitoringCertificate, 0, len(certificates))
	for _, value := range certificates {
		certificate := value
		list = append(list, &certificate)
	}
	return list, nil
}

func (db *CertificatesMonitoringMockup) Revoke(organizationId string, certificateId string) derrors.Error {
	certificate, err := db.Get(organizationId, certificateId)
	if err != nil {
		return err
	}
	certificate.RevocationTimestamp = time.Now().UnixNano()
	return nil
}

func (db *CertificatesMonitoringMockup) Truncate() derrors.Error {
	db.data = make(map[string]map[string]entities.MonitoringCertificate)
	return nil
}
