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

package handler

import (
	"context"
	"github.com/nalej/authx/internal/app/authx/manager"
	"github.com/nalej/authx/internal/app/entities"
	"github.com/nalej/derrors"
	"github.com/nalej/grpc-authx-go"
	pbAuthx "github.com/nalej/grpc-authx-go"
	pbCommon "github.com/nalej/grpc-common-go"
	"github.com/nalej/grpc-device-go"
	"github.com/nalej/grpc-organization-go"
	"github.com/nalej/grpc-user-go"
	"github.com/nalej/grpc-utils/pkg/conversions"
)

// MinPasswordLength Minimum password length for user credentials set to 6
const MinPasswordLength = 6

// Authx is the struct that handles the gRPC service.
type Authx struct {
	// Manager is the struct responsible of the service business logic.
	Manager *manager.Authx
}

// NewAuthx creates a new handler.
func NewAuthx(manager *manager.Authx) *Authx {
	return &Authx{Manager: manager}
}

// DeleteCredentials remove an existing credential using the username.
func (h *Authx) DeleteCredentials(_ context.Context, request *pbAuthx.DeleteCredentialsRequest) (*pbCommon.Success, error) {
	if request.Username == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("username is mandatory"))
	}
	err := h.Manager.DeleteCredentials(request.Username)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return &pbCommon.Success{}, nil
}

// AddBasicCredentials adds a new credential specifying a password.
func (h *Authx) AddBasicCredentials(_ context.Context, request *pbAuthx.AddBasicCredentialRequest) (*pbCommon.Success, error) {
	if request.Username == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("username is mandatory"))
	}
	if request.OrganizationId == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("organizationID is mandatory"))
	}
	if request.RoleId == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("roleID is mandatory"))
	}
	if request.Password == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("password is mandatory"))
	}
	if err := ValidatePassword(request.Password); err != nil {
		return nil, err
	}

	err := h.Manager.AddBasicCredentials(request.Username, request.OrganizationId, request.RoleId, request.Password)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return &pbCommon.Success{}, nil
}

// ChangePassword update an existing password.
func (h *Authx) ChangePassword(ctx context.Context, request *pbAuthx.ChangePasswordRequest) (*pbCommon.Success, error) {
	if request.Username == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("username is mandatory"))
	}

	if request.NewPassword == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("newPassword is mandatory"))
	}
	if err := ValidatePassword(request.NewPassword); err != nil {
		return nil, err
	}

	err := h.Manager.ChangePassword(request.Username, request.NewPassword)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return &pbCommon.Success{}, nil
}

func ValidatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return conversions.ToGRPCError(derrors.NewInvalidArgumentError("password must be at least 6 characters long"))
	}
	return nil
}

// LoginWithBasicCredentials login in the system and recovers a auth token.
func (h *Authx) LoginWithBasicCredentials(_ context.Context, request *pbAuthx.LoginWithBasicCredentialsRequest) (*pbAuthx.LoginResponse, error) {
	if request.Username == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("username is mandatory"))
	}
	if request.Password == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("password is mandatory"))
	}

	response, err := h.Manager.LoginWithBasicCredentials(request.Username, request.Password)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return response, nil
}

// RefreshToken renews an existing token.
func (h *Authx) RefreshToken(_ context.Context, request *pbAuthx.RefreshTokenRequest) (*pbAuthx.LoginResponse, error) {

	if request.RefreshToken == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("refreshToken is mandatory"))
	}

	if request.Token == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("token is mandatory"))
	}

	response, err := h.Manager.RefreshToken(request.Token, request.RefreshToken)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return response, nil
}

// AddRole adds a role with a authorization properties.
func (h *Authx) AddRole(_ context.Context, request *pbAuthx.Role) (*pbCommon.Success, error) {
	if request.RoleId == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("roleID is mandatory"))
	}
	if request.Name == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("name is mandatory"))
	}
	if request.OrganizationId == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("organizationID is mandatory"))
	}
	if request.Primitives == nil || len(request.Primitives) == 0 {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("primitives is mandatory"))
	}

	err := h.Manager.AddRole(request)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return &pbCommon.Success{}, nil
}

// EditUserRole change the roleID to a specific user.
func (h *Authx) EditUserRole(_ context.Context, request *pbAuthx.EditUserRoleRequest) (*pbCommon.Success, error) {
	if request.Username == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("username is mandatory"))
	}
	if request.NewRoleId == "" {
		return nil, conversions.ToGRPCError(derrors.NewInvalidArgumentError("newRoleID is mandatory"))
	}
	err := h.Manager.EditUserRole(request.Username, request.NewRoleId)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return &pbCommon.Success{}, nil
}

// ListRoles returns a list of roles inside an organization.
func (h *Authx) ListRoles(ctx context.Context, organizationID *grpc_organization_go.OrganizationId) (*grpc_authx_go.RoleList, error) {
	vErr := entities.ValidOrganizationID(organizationID)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}
	roles, err := h.Manager.ListRoles(organizationID)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	result := make([]*grpc_authx_go.Role, 0)
	for _, r := range roles {
		result = append(result, r.ToGRPC())
	}
	return &grpc_authx_go.RoleList{
		Roles: result,
	}, nil
}

// GetUserRole retrieves the role associated with a user.
func (h *Authx) GetUserRole(ctx context.Context, userID *grpc_user_go.UserId) (*grpc_authx_go.Role, error) {
	vErr := entities.ValidUserID(userID)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}
	retrieved, err := h.Manager.GetUserRole(userID)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return retrieved.ToGRPC(), nil
}

//
func (h *Authx) GetUserAuthxInfo(ctx context.Context, userId *grpc_user_go.UserId) (*grpc_authx_go.UserAuthxInfo, error) {
	vErr := entities.ValidUserID(userId)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}
	retrieved, err := h.Manager.GetUserAuthxInfo(userId)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return retrieved.ToGRPC(), nil
}

// -- Device Credentials -- //
func (h *Authx) AddDeviceCredentials(ctx context.Context, request *pbAuthx.AddDeviceCredentialsRequest) (*pbAuthx.DeviceCredentials, error) {
	vErr := entities.ValidAddDeviceCredentials(request)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}

	added, err := h.Manager.AddDeviceCredentials(request)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}

	return added.ToGRPC(), nil

}

// UpdateDeviceCredentials enable /disable the device
func (h *Authx) UpdateDeviceCredentials(ctx context.Context, request *pbAuthx.UpdateDeviceCredentialsRequest) (*pbCommon.Success, error) {

	vErr := entities.ValidUpdateDeviceCredentialsRequest(request)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}

	err := h.Manager.UpdateDeviceCredentials(request)

	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}

	return &pbCommon.Success{}, nil
}

// GetDeviceCredentials retrieves the credentials associated with a device
func (h *Authx) GetDeviceCredentials(ctx context.Context, request *grpc_device_go.DeviceId) (*pbAuthx.DeviceCredentials, error) {
	vErr := entities.ValidDeviceID(request)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}

	credentials, err := h.Manager.GetDeviceCredentials(request)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return credentials.ToGRPC(), nil

}

// RemoveDeviceCredentials removes a credential
func (h *Authx) RemoveDeviceCredentials(ctx context.Context, credentials *grpc_device_go.DeviceId) (*pbCommon.Success, error) {

	vErr := entities.ValidDeviceID(credentials)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}

	err := h.Manager.RemoveDeviceCredentials(credentials)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return &pbCommon.Success{}, nil

}

// DeviceLogin checks if the device credentials are valid and returns a token
func (h *Authx) DeviceLogin(ctx context.Context, loginRequest *pbAuthx.DeviceLoginRequest) (*pbAuthx.LoginResponse, error) {

	vErr := entities.ValidDeviceLoginRequest(loginRequest)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}

	response, err := h.Manager.LoginDeviceCredentials(loginRequest)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return response, nil
}

// AddDeviceGroupCredentials adds a device in the system
func (h *Authx) AddDeviceGroupCredentials(ctx context.Context, request *pbAuthx.AddDeviceGroupCredentialsRequest) (*pbAuthx.DeviceGroupCredentials, error) {
	vErr := entities.ValidAddDeviceGroupCredentials(request)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}

	added, err := h.Manager.AddDeviceGroupCredentials(request)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}

	return added.ToGRPC(), nil
}

// UpdateDeviceGroupCredentials enable /disable the device
func (h *Authx) UpdateDeviceGroupCredentials(ctx context.Context, request *pbAuthx.UpdateDeviceGroupCredentialsRequest) (*pbCommon.Success, error) {
	vErr := entities.ValidUpdateDeviceGroupCredentialsRequest(request)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}

	err := h.Manager.UpdateDeviceGroupCredentials(request)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}

	return &pbCommon.Success{}, nil
}

// GetDeviceGroupCredentials retrieves retrieves the credentials associated with a device group
func (h *Authx) GetDeviceGroupCredentials(ctx context.Context, request *grpc_device_go.DeviceGroupId) (*pbAuthx.DeviceGroupCredentials, error) {
	vErr := entities.ValidDeviceGroupID(request)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}

	credentials, err := h.Manager.GetDeviceGroupCredentials(request)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return credentials.ToGRPC(), nil

}

// RemoveDeviceGroupCredentials removes a group credentials
func (h *Authx) RemoveDeviceGroupCredentials(ctx context.Context, credentials *grpc_device_go.DeviceGroupId) (*pbCommon.Success, error) {
	vErr := entities.ValidDeviceGroupID(credentials)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}

	err := h.Manager.RemoveDeviceGroupCredentials(credentials)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return &pbCommon.Success{}, nil

}

// DeviceGroupLogin checks if the device group credentials are valid
func (h *Authx) DeviceGroupLogin(ctx context.Context, credentials *grpc_authx_go.DeviceGroupLoginRequest) (*pbCommon.Success, error) {
	vErr := entities.ValidDeviceGroupLoginRequest(credentials)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}
	err := h.Manager.LoginDeviceGroup(credentials)
	if err != nil {
		return nil, err
	}

	return &pbCommon.Success{}, nil

}

// RefreshDeviceToken renews an existing token.
func (h *Authx) RefreshDeviceToken(_ context.Context, request *pbAuthx.RefreshTokenRequest) (*pbAuthx.LoginResponse, error) {

	vErr := entities.ValidRefreshToken(request)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}

	response, err := h.Manager.RefreshDeviceToken(request.Token, request.RefreshToken)
	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return response, nil
}

func (h *Authx) GetDeviceGroupSecret(context context.Context, request *grpc_device_go.DeviceGroupId) (*pbAuthx.DeviceGroupSecret, error) {
	vErr := entities.ValidDeviceGroupID(request)
	if vErr != nil {
		return nil, conversions.ToGRPCError(vErr)
	}
	secret, err := h.Manager.GetDeviceGroupSecret(request)

	if err != nil {
		return nil, conversions.ToGRPCError(err)
	}
	return secret, nil
}
