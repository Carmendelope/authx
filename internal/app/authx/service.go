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

package authx

import (
	"fmt"
	"github.com/nalej/authx/internal/app/authx/certificates"
	"github.com/nalej/authx/internal/app/authx/config"
	"github.com/nalej/authx/internal/app/authx/handler"
	"github.com/nalej/authx/internal/app/authx/inventory"
	"github.com/nalej/authx/internal/app/authx/manager"
	"github.com/nalej/authx/internal/app/authx/providers/certificates_monitoring"
	"github.com/nalej/authx/internal/app/authx/providers/credentials"
	"github.com/nalej/authx/internal/app/authx/providers/device"
	"github.com/nalej/authx/internal/app/authx/providers/device_token"
	inventoryProv "github.com/nalej/authx/internal/app/authx/providers/inventory"
	"github.com/nalej/authx/internal/app/authx/providers/role"
	"github.com/nalej/authx/internal/app/authx/providers/token"
	pbAuthx "github.com/nalej/grpc-authx-go"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"net"
)

// Service is the Authx service instance.
type Service struct {
	// Config is the required parameters.
	config.Config
}

type Providers struct {
	roleProvider      role.Role
	credProvider      credentials.BasicCredentials
	devProvider       device.Provider
	tokenProvider     token.Token
	devTokenProvider  device_token.Provider
	inventoryProvider inventoryProv.Provider
	certProvider      certificates_monitoring.CertificatesMonitoring
}

type TokenManagers struct {
	tokenManager       manager.Token
	deviceTokenManager manager.DeviceToken
}

// NewService create a new service instance.
func NewService(config config.Config) *Service {
	return &Service{Config: config}
}

func (s *Service) CreateInMemoryProviders() *Providers {
	return &Providers{
		roleProvider:      role.NewRoleMockup(),
		credProvider:      credentials.NewBasicCredentialMockup(),
		devProvider:       device.NewMockupDeviceCredentialsProvider(),
		tokenProvider:     token.NewTokenMockup(),
		devTokenProvider:  device_token.NewDeviceTokenMockup(),
		inventoryProvider: inventoryProv.NewMockupInventoryProvider(),
		certProvider:      certificates_monitoring.NewCertificatesMonitoringMockup(),
	}
}

func (s *Service) CreateDBScyllaProviders() *Providers {
	return &Providers{
		roleProvider: role.NewScyllaRoleProvider(
			s.Config.ScyllaDBAddress, s.Config.ScyllaDBPort, s.Config.KeySpace),
		credProvider: credentials.NewScyllaCredentialsProvider(
			s.Config.ScyllaDBAddress, s.Config.ScyllaDBPort, s.Config.KeySpace),
		devProvider: device.NewScyllaDeviceCredentialsProvider(
			s.Config.ScyllaDBAddress, s.Config.ScyllaDBPort, s.Config.KeySpace),
		tokenProvider: token.NewScyllaTokenProvider(
			s.Config.ScyllaDBAddress, s.Config.ScyllaDBPort, s.Config.KeySpace),
		devTokenProvider: device_token.NewScyllaDeviceTokenProvider(
			s.Config.ScyllaDBAddress, s.Config.ScyllaDBPort, s.Config.KeySpace),
		// TODO Use an scylladb provider
		inventoryProvider: inventoryProv.NewMockupInventoryProvider(),
		certProvider: certificates_monitoring.NewCertificatesMonitoringScyllaProvider(
			s.Config.ScyllaDBAddress, s.Config.ScyllaDBPort, s.Config.KeySpace),
	}
}

// GetProviders builds the providers according to the selected backend.
func (s *Service) GetProviders() *Providers {
	if s.Config.UseInMemoryProviders {
		return s.CreateInMemoryProviders()
	} else if s.Config.UseDBScyllaProviders {
		return s.CreateDBScyllaProviders()
	}
	log.Fatal().Msg("unsupported type of provider")
	return nil
}

func (s *Service) createInMemoryManagers() *TokenManagers {
	return &TokenManagers{
		tokenManager:       manager.NewJWTTokenMockup(),
		deviceTokenManager: manager.NewJWTDeviceTokenMockup(),
	}
}
func (s *Service) createDBScyllaManagers(tokenProvider token.Token, password manager.Password,
	deviceProvider device.Provider, deviceTokenProvider device_token.Provider) *TokenManagers {
	return &TokenManagers{
		tokenManager:       manager.NewJWTToken(tokenProvider, password),
		deviceTokenManager: manager.NewJWTDeviceToken(deviceProvider, deviceTokenProvider),
	}
}

func (s *Service) getTokenManager(tokenProvider token.Token, password manager.Password,
	deviceProvider device.Provider, deviceTokenProvider device_token.Provider) *TokenManagers {
	if s.Config.UseInMemoryProviders {
		return s.createInMemoryManagers()
	} else if s.Config.UseDBScyllaProviders {
		return s.createDBScyllaManagers(tokenProvider, password, deviceProvider, deviceTokenProvider)
	}
	log.Fatal().Msg("unsupported type of provider")
	return nil
}

//Run launch the Authx service.
func (s *Service) Run() {
	vErr := s.Config.Validate()
	if vErr != nil {
		log.Fatal().Str("error", vErr.DebugReport()).Msg("Invalid configuration")
	}
	s.Config.Print()
	p := s.GetProviders()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		log.Fatal().Errs("failed to listen: %v", []error{err})
		return
	}

	passwordMgr := manager.NewBCryptPassword()

	// Create the token manager (memory/scylla)
	t := s.getTokenManager(p.tokenProvider, passwordMgr, p.devProvider, p.devTokenProvider)
	tokenMgr := t.tokenManager
	deviceMgr := t.deviceTokenManager

	authxMgr := manager.NewAuthx(passwordMgr, tokenMgr, deviceMgr, p.credProvider, p.roleProvider, p.devProvider,
		s.Secret, s.ExpirationTime, s.DeviceExpirationTime, p.devTokenProvider)

	h := handler.NewAuthx(authxMgr)

	inventoryManager := inventory.NewManager(p.inventoryProvider, s.Config)
	inventoryHandler := inventory.NewHandler(inventoryManager)

	helper, cErr := certificates.NewCertHelper(s.Config.CACertPath, s.Config.CAPrivateKeyPath)
	if cErr != nil {
		log.Fatal().Str("trace", cErr.DebugReport()).Msg("cannot create certificate helper")
		return
	}
	certManager := certificates.NewManager(s.Config, helper, p.certProvider)
	certHandler := certificates.NewHandler(certManager)

	grpcServer := grpc.NewServer()

	pbAuthx.RegisterAuthxServer(grpcServer, h)
	pbAuthx.RegisterInventoryServer(grpcServer, inventoryHandler)
	pbAuthx.RegisterCertificatesServer(grpcServer, certHandler)

	if s.Config.Debug {
		log.Info().Msg("Enabling gRPC server reflection")
		// Register reflection service on gRPC server.
		reflection.Register(grpcServer)
	}

	log.Info().Int("Port", s.Port).Msg("Launching gRPC server")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal().Errs("failed to serve: %v", []error{err})
	}
}
