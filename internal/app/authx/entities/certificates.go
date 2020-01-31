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

package entities

import (
	"github.com/nalej/derrors"
	"github.com/nalej/grpc-authx-go"
)

// MonitoringCertificate represents the certificate info that is stored.
type MonitoringCertificate struct {
	// OrganizationId which the certificate belongs to.
	OrganizationId string
	// CertificateId
	CertificateId string
	// CreationTimestamp
	CreationTimestamp int64
	// ExpirationTimestamp
	ExpirationTimestamp int64
	// RevocationTimestamp
	RevocationTimestamp int64
}

// NewMonitoringCertificate creates a new Certificate info object.
func NewMonitoringCertificate(organizationId string, certificateId string, creationTimestamp int64, expirationTimestamp int64, revocationTimestamp int64) *MonitoringCertificate {
	return &MonitoringCertificate{
		OrganizationId:      organizationId,
		CertificateId:       certificateId,
		CreationTimestamp:   creationTimestamp,
		ExpirationTimestamp: expirationTimestamp,
		RevocationTimestamp: revocationTimestamp,
	}
}

func ValidEdgeControllerCertRequest(request *grpc_authx_go.EdgeControllerCertRequest) derrors.Error {
	if request.OrganizationId == "" {
		return derrors.NewInvalidArgumentError("organization_id cannot be empty")
	}
	if request.EdgeControllerId == "" {
		return derrors.NewInvalidArgumentError("edge_controller_id cannot be empty")
	}
	return nil
}

func ValidateCreateMonitoringClientCertificateRequest(request *grpc_authx_go.CreateMonitoringClientCertificateRequest) derrors.Error {
	if request.OrganizationId == "" {
		return derrors.NewInvalidArgumentError("organization_id cannot be empty")
	}
	return nil
}
