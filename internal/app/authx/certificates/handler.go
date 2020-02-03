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
	"context"
	"github.com/nalej/authx/internal/app/authx/entities"
	"github.com/nalej/grpc-authx-go"
	"github.com/nalej/grpc-common-go"
	"github.com/nalej/grpc-utils/pkg/conversions"
	"github.com/rs/zerolog/log"
)

type Handler struct {
	manager Manager
}

func NewHandler(manager Manager) *Handler {
	return &Handler{
		manager,
	}
}

// CreateControllerCert creates a certificate for an edge controller.
func (h *Handler) CreateControllerCert(ctx context.Context, request *grpc_authx_go.EdgeControllerCertRequest) (*grpc_authx_go.PEMCertificate, error) {
	vErr := entities.ValidEdgeControllerCertRequest(request)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}
	pem, err := h.manager.CreateControllerCert(request)
	if err != nil {
		log.Warn().Str("trace", err.DebugReport()).Msg("cannot create ")
		return nil, conversions.ToGRPCError(err)
	}
	return pem, nil
}

// CreateMonitoringClientCertificate creates a new certificate for the monitoring endpoint for the given organization.
func (h *Handler) CreateMonitoringClientCertificate(ctx context.Context, request *grpc_authx_go.CreateMonitoringClientCertificateRequest) (*grpc_authx_go.CreateMonitoringClientCertificateResponse, error) {
	err := entities.ValidateCreateMonitoringClientCertificateRequest(request)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	response, err := h.manager.CreateMonitoringClientCertificate(request)
	if err != nil {
		log.Error().
			Err(err).
			Str("trace", err.DebugReport()).
			Interface("request", request).
			Msg("there was an error creating monitoring client certificates")
		return nil, conversions.ToGRPCError(err)
	}
	return response, nil
}

// ListMonitoringClientCertificates lists all the monitoring certificates of the given organization.
func (h *Handler) ListMonitoringClientCertificates(ctx context.Context, request *grpc_authx_go.ListMonitoringClientCertificateRequest) (*grpc_authx_go.ListMonitoringClientCertificateResponse, error) {
	err := entities.ValidateListMonitoringClientCertificateRequest(request)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	response, err := h.manager.ListMonitoringClientCertificates(request)
	if err != nil {
		log.Error().
			Err(err).
			Str("trace", err.DebugReport()).
			Interface("request", request).
			Msg("there was an error listing monitoring client certificates")
		return nil, conversions.ToGRPCError(err)
	}
	return response, nil
}

// ValidateMonitoringCertificate checks if the given certificate is still valid.
func (h *Handler) ValidateMonitoringCertificate(ctx context.Context, request *grpc_authx_go.ValidateMonitoringClientCertificateRequest) (*grpc_common_go.Success, error) {
	err := entities.ValidateMonitoringClientCertificateValidationRequest(request)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	response, err := h.manager.ValidateMonitoringCertificate(request)
	if err != nil {
		log.Error().
			Err(err).
			Str("trace", err.DebugReport()).
			Interface("request", request).
			Msg("there was an error validating monitoring client certificate")
		return nil, conversions.ToGRPCError(err)
	}
	return response, nil
}

// RevokeMonitoringCertificate revokes the given certificate.
func (h *Handler) RevokeMonitoringCertificate(ctx context.Context, request *grpc_authx_go.RevokeMonitoringClientCertificateRequest) (*grpc_common_go.Success, error) {
	err := entities.ValidateRevokeMonitoringClientCertificateRequest(request)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	response, err := h.manager.RevokeMonitoringCertificate(request)
	if err != nil {
		log.Error().
			Err(err).
			Str("trace", err.DebugReport()).
			Interface("request", request).
			Msg("there was an error revoking monitoring client certificate")
		return nil, conversions.ToGRPCError(err)
	}
	return response, nil
}
