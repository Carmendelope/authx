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
 *
 */

package certificates_monitoring

import (
	"github.com/nalej/authx/internal/app/authx/entities"
	"github.com/nalej/derrors"
)

// CertificatesMonitoring is the interface that define how to interact with monitoring certificates.
type CertificatesMonitoring interface {
	// Add a new monitoring certificate.
	Add(certificate *entities.MonitoringCertificate) derrors.Error
	// Get a specific monitoring certificate.
	Get(organizationId string, certificateId string) (*entities.MonitoringCertificate, derrors.Error)
	// List all the monitoring certificates of the organization.
	List(organizationId string) ([]*entities.MonitoringCertificate, derrors.Error)
	// Revoke a specific monitoring certificate.
	Revoke(organizationId string, certificateId string) derrors.Error
	// Truncate cleans all the records of monitoring certificates.
	Truncate() derrors.Error
}
