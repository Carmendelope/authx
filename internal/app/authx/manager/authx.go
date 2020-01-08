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

package manager

import (
	"github.com/nalej/authx/internal/app/authx/entities"
	"github.com/nalej/authx/internal/app/authx/providers/credentials"
	"github.com/nalej/authx/internal/app/authx/providers/device"
	"github.com/nalej/authx/internal/app/authx/providers/device_token"
	"github.com/nalej/authx/internal/app/authx/providers/role"
	"github.com/nalej/authx/pkg/token"
	"github.com/nalej/derrors"
	pbAuthx "github.com/nalej/grpc-authx-go"
	"github.com/nalej/grpc-device-go"
	"github.com/nalej/grpc-organization-go"
	"github.com/nalej/grpc-user-go"
	"time"
)

// DefaultExpirationDuration is the default duration used in the mockup.
const DefaultExpirationDuration = "10h"
const DefaultDeviceExpirationDuration = "10m"

// DefaultSecret is the default secret used in the mockup.
const DefaultSecret = "MyLittleSecret"

// Authx is the component that manages the business logic.
type Authx struct {
	Password            Password
	Token               Token                        // user_token
	CredentialsProvider credentials.BasicCredentials // user_credentials
	RoleProvider        role.Role                    // role Provider
	DeviceProvider      device.Provider              // device Provider
	secret              string                       // Secret (for user login)
	expirationDuration  time.Duration                // user token expiration
	DeviceToken         DeviceToken                  // device_token
	DeviceExpiration    time.Duration                // device_token expiration
	DeviceTokenProvider device_token.Provider
}

// NewAuthx creates a new manager.
func NewAuthx(password Password, tokenManager Token, deviceToken DeviceToken, credentialsProvider credentials.BasicCredentials,
	roleProvide role.Role, deviceProvider device.Provider, secret string, expirationDuration time.Duration, deviceExpiration time.Duration,
	deviceTokenProvider device_token.Provider) *Authx {

	return &Authx{
		Password:            password,
		Token:               tokenManager,
		CredentialsProvider: credentialsProvider,
		RoleProvider:        roleProvide,
		DeviceProvider:      deviceProvider,
		secret:              secret,
		expirationDuration:  expirationDuration,
		DeviceToken:         deviceToken,
		DeviceExpiration:    deviceExpiration,
		DeviceTokenProvider: deviceTokenProvider,
	}

}

// NewAuthxMockup create a new mockup manager.
func NewAuthxMockup() *Authx {
	d, _ := time.ParseDuration(DefaultExpirationDuration)
	e, _ := time.ParseDuration(DefaultDeviceExpirationDuration)
	dcProvider := device.NewMockupDeviceCredentialsProvider()
	dtMockup := device_token.NewDeviceTokenMockup()
	return NewAuthx(NewBCryptPassword(), NewJWTTokenMockup(), NewJWTDeviceToken(dcProvider, dtMockup),
		credentials.NewBasicCredentialMockup(), role.NewRoleMockup(),
		dcProvider, DefaultSecret, d, e,
		dtMockup)
}

// DeleteCredentials deletes the credential for a specific username.
func (m *Authx) DeleteCredentials(username string) derrors.Error {
	return m.CredentialsProvider.Delete(username)
}

// AddBasicCredentials generate credential for a specific user.
func (m *Authx) AddBasicCredentials(username string, organizationID string, roleID string, password string) derrors.Error {
	_, err := m.RoleProvider.Get(organizationID, roleID)
	if err != nil {
		return err
	}

	exist, err := m.CredentialsProvider.Exist(username)
	if err != nil {
		return err
	}
	if *exist {
		return derrors.NewAlreadyExistsError("credentials already exists")
	}

	hashedPassword, err := m.Password.GenerateHashedPassword(password)
	if err != nil {
		return err
	}

	entity := entities.NewBasicCredentialsData(username, hashedPassword, roleID, organizationID)
	return m.CredentialsProvider.Add(entity)
}

// LoginWithBasicCredentials check the password and returns a valid token.
func (m *Authx) LoginWithBasicCredentials(username string, password string) (*pbAuthx.LoginResponse, derrors.Error) {
	credentials, err := m.CredentialsProvider.Get(username)
	if err != nil {
		return nil, err
	}
	err = m.Password.CompareHashAndPassword(credentials.Password, password)
	if err != nil {
		return nil, err
	}
	role, err := m.RoleProvider.Get(credentials.OrganizationID, credentials.RoleID)
	if err != nil {
		return nil, err
	}
	personalClaim := token.NewPersonalClaim(username, role.Name, role.Primitives, credentials.OrganizationID)
	gToken, err := m.Token.Generate(personalClaim, m.expirationDuration, m.secret)
	if err != nil {

		return nil, err
	}

	response := &pbAuthx.LoginResponse{Token: gToken.Token, RefreshToken: gToken.RefreshToken}

	err = m.SetLastLoginTimestamp(username)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (m *Authx) SetLastLoginTimestamp(username string) derrors.Error {
	loginData := &entities.EditBasicCredentialsData{
		LastLogin: time.Now().UnixNano(),
	}
	err := m.CredentialsProvider.Edit(username, loginData)
}

func (m *Authx) ChangePassword(username string, password string, newPassword string) derrors.Error {
	credentials, err := m.CredentialsProvider.Get(username)
	if err != nil {
		return err
	}
	err = m.Password.CompareHashAndPassword(credentials.Password, password)
	if err != nil {
		return err
	}
	hashedPassword, err := m.Password.GenerateHashedPassword(newPassword)
	if err != nil {
		return err
	}
	edit := entities.NewEditBasicCredentialsData().WithPassword(hashedPassword)
	return m.CredentialsProvider.Edit(username, edit)
}

// RefreshToken renew an old token.
func (m *Authx) RefreshToken(oldToken string, refreshToken string) (*pbAuthx.LoginResponse, derrors.Error) {
	gToken, err := m.Token.Refresh(oldToken, refreshToken, m.expirationDuration, m.secret)
	if err != nil {
		return nil, err
	}
	response := &pbAuthx.LoginResponse{Token: gToken.Token, RefreshToken: gToken.RefreshToken}
	return response, nil
}

// AddRole add a new role to the authorization system.
func (m *Authx) AddRole(role *pbAuthx.Role) derrors.Error {
	entity := entities.NewRoleData(role.OrganizationId, role.RoleId, role.Name, role.Internal, PrimitivesToString(role.Primitives))
	return m.RoleProvider.Add(entity)
}

// EditUserRole change the RoleID to a specific user.
func (m *Authx) EditUserRole(username string, roleID string) derrors.Error {
	credentials, err := m.CredentialsProvider.Get(username)
	if err != nil {
		return err
	}
	role, err := m.RoleProvider.Get(credentials.OrganizationID, roleID)
	if err != nil {
		return err
	}

	if role == nil {
		return derrors.NewNotFoundError("role not found")
	}

	edit := entities.NewEditBasicCredentialsData().WithRoleID(roleID)
	return m.CredentialsProvider.Edit(username, edit)
}

func (m *Authx) ListRoles(organizationID *grpc_organization_go.OrganizationId) ([]entities.RoleData, derrors.Error) {
	return m.RoleProvider.List(organizationID.OrganizationId)
}

func (m *Authx) GetUserRole(userID *grpc_user_go.UserId) (*entities.RoleData, derrors.Error) {
	cred, err := m.CredentialsProvider.Get(userID.Email)
	if err != nil {
		return nil, err
	}
	return m.RoleProvider.Get(userID.OrganizationId, cred.RoleID)
}

// Clean removes all the data.
func (m *Authx) Clean() derrors.Error {
	err := m.Token.Clean()
	if err != nil {
		return err
	}
	err = m.CredentialsProvider.Truncate()
	if err != nil {
		return err
	}
	err = m.RoleProvider.Truncate()
	if err != nil {
		return err
	}
	err = m.DeviceProvider.Truncate()
	if err != nil {
		return err
	}

	return nil
}

// PrimitivesToString transform the primitive to strings.
func PrimitivesToString(primitives []pbAuthx.AccessPrimitive) []string {
	strPrimitives := make([]string, 0, len(primitives))
	for _, p := range primitives {
		strPrimitives = append(strPrimitives, p.String())
	}
	return strPrimitives
}

// -- Device Credentials -- //
func (m *Authx) AddDeviceCredentials(deviceCredentials *pbAuthx.AddDeviceCredentialsRequest) (*entities.DeviceCredentials, derrors.Error) {

	// Check if the group exists
	exists, err := m.DeviceProvider.ExistsDeviceGroup(deviceCredentials.OrganizationId, deviceCredentials.DeviceGroupId)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, derrors.NewNotFoundError("deviceGroupID").WithParams(deviceCredentials.OrganizationId, deviceCredentials.DeviceGroupId)
	}

	// Get the group to review if it is enable
	group, err := m.DeviceProvider.GetDeviceGroup(deviceCredentials.OrganizationId, deviceCredentials.DeviceGroupId)
	if err != nil {
		return nil, err
	}
	if !group.Enabled {
		return nil, derrors.NewPermissionDeniedError("the group is temporarily disabled").WithParams(deviceCredentials.OrganizationId, deviceCredentials.DeviceGroupId)
	}

	toAdd := entities.NewDeviceCredentialsFromGRPC(deviceCredentials)
	// the device will be enable or disabled depending at group default value
	toAdd.Enabled = group.DefaultDeviceConnectivity

	err = m.DeviceProvider.AddDeviceCredentials(toAdd)
	if err != nil {
		return nil, err
	}
	return toAdd, nil
}

func (m *Authx) UpdateDeviceCredentials(deviceCredentials *pbAuthx.UpdateDeviceCredentialsRequest) derrors.Error {
	// Check if the credentials exists
	exists, err := m.DeviceProvider.ExistsDevice(deviceCredentials.OrganizationId, deviceCredentials.DeviceGroupId, deviceCredentials.DeviceId)
	if err != nil {
		return err
	}
	if !exists {
		return derrors.NewNotFoundError("device credentials").WithParams(deviceCredentials.OrganizationId, deviceCredentials.DeviceGroupId, deviceCredentials.DeviceId)
	}

	toUpdate, err := m.DeviceProvider.GetDevice(deviceCredentials.OrganizationId, deviceCredentials.DeviceGroupId, deviceCredentials.DeviceId)
	if err != nil {
		return err
	}

	toUpdate.Enabled = deviceCredentials.Enabled

	err = m.DeviceProvider.UpdateDeviceCredentials(toUpdate)
	if err != nil {
		return err
	}

	return nil
}

func (m *Authx) GetDeviceCredentials(request *grpc_device_go.DeviceId) (*entities.DeviceCredentials, derrors.Error) {
	// Check if the credentials group exist
	exists, err := m.DeviceProvider.ExistsDeviceGroup(request.OrganizationId, request.DeviceGroupId)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, derrors.NewNotFoundError("device group credentials").WithParams(request.OrganizationId, request.DeviceGroupId)
	}
	// Check if the credentials device exist
	exists, err = m.DeviceProvider.ExistsDevice(request.OrganizationId, request.DeviceGroupId, request.DeviceId)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, derrors.NewNotFoundError("device credentials").WithParams(request.OrganizationId, request.DeviceGroupId, request.DeviceId)
	}

	credentials, err := m.DeviceProvider.GetDevice(request.OrganizationId, request.DeviceGroupId, request.DeviceId)
	if err != nil {
		return nil, err
	}
	return credentials, nil
}

func (m *Authx) RemoveDeviceCredentials(deviceCredentials *grpc_device_go.DeviceId) derrors.Error {

	exists, err := m.DeviceProvider.ExistsDevice(deviceCredentials.OrganizationId, deviceCredentials.DeviceGroupId, deviceCredentials.DeviceId)
	if err != nil {
		return err
	}
	if !exists {
		return derrors.NewNotFoundError("device credentials").WithParams(deviceCredentials.OrganizationId, deviceCredentials.DeviceGroupId, deviceCredentials.DeviceId)
	}

	err = m.DeviceProvider.RemoveDevice(deviceCredentials.OrganizationId, deviceCredentials.DeviceGroupId, deviceCredentials.DeviceId)
	if err != nil {
		return err
	}

	return nil
}

func (m *Authx) LoginDeviceCredentials(loginRequest *pbAuthx.DeviceLoginRequest) (*pbAuthx.LoginResponse, derrors.Error) {

	credentials, err := m.DeviceProvider.GetDeviceByApiKey(loginRequest.DeviceApiKey)
	if err != nil {
		return nil, err
	}

	if credentials.OrganizationID != loginRequest.OrganizationId {
		return nil, derrors.NewUnauthenticatedError("Invalid credentials")
	}

	// Get the group to review if it is enable
	group, err := m.DeviceProvider.GetDeviceGroup(credentials.OrganizationID, credentials.DeviceGroupID)
	if err != nil {
		return nil, err
	}
	// if the group is disabled, the login is not allowed
	if !group.Enabled {
		return nil, derrors.NewPermissionDeniedError("the group is temporarily disabled").WithParams(credentials.OrganizationID, credentials.DeviceGroupID)
	}

	deviceClaim := token.NewDeviceClaim(credentials.OrganizationID, credentials.DeviceGroupID, credentials.DeviceID, m.DeviceExpiration)

	gToken, err := m.DeviceToken.Generate(deviceClaim, m.DeviceExpiration, group.Secret)
	if err != nil {

		return nil, err
	}
	response := &pbAuthx.LoginResponse{Token: gToken.Token, RefreshToken: gToken.RefreshToken}

	return response, nil

}

func (m *Authx) AddDeviceGroupCredentials(groupCredentials *pbAuthx.AddDeviceGroupCredentialsRequest) (*entities.DeviceGroupCredentials, derrors.Error) {

	toAdd := entities.NewDeviceGroupCredentialsFromGRPC(groupCredentials)
	err := m.DeviceProvider.AddDeviceGroupCredentials(toAdd)
	if err != nil {
		return nil, err
	}
	return toAdd, nil
}

func (m *Authx) UpdateDeviceGroupCredentials(groupCredentials *pbAuthx.UpdateDeviceGroupCredentialsRequest) derrors.Error {
	// Check if the credentials exists
	exists, err := m.DeviceProvider.ExistsDeviceGroup(groupCredentials.OrganizationId, groupCredentials.DeviceGroupId)
	if err != nil {
		return err
	}
	if !exists {
		return derrors.NewNotFoundError("device group credentials").WithParams(groupCredentials.OrganizationId, groupCredentials.DeviceGroupId)
	}

	toUpdate, err := m.DeviceProvider.GetDeviceGroup(groupCredentials.OrganizationId, groupCredentials.DeviceGroupId)
	if err != nil {
		return err
	}
	if groupCredentials.UpdateEnabled {
		toUpdate.Enabled = groupCredentials.Enabled
	}
	if groupCredentials.UpdateDeviceConnectivity {
		toUpdate.DefaultDeviceConnectivity = groupCredentials.DefaultDeviceConnectivity
	}

	err = m.DeviceProvider.UpdateDeviceGroupCredentials(toUpdate)
	if err != nil {
		return err
	}

	return nil
}

func (m *Authx) GetDeviceGroupCredentials(request *grpc_device_go.DeviceGroupId) (*entities.DeviceGroupCredentials, derrors.Error) {
	// Check if the credentials exists
	exists, err := m.DeviceProvider.ExistsDeviceGroup(request.OrganizationId, request.DeviceGroupId)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, derrors.NewNotFoundError("device group credentials").WithParams(request.OrganizationId, request.DeviceGroupId)
	}

	group, err := m.DeviceProvider.GetDeviceGroup(request.OrganizationId, request.DeviceGroupId)
	if err != nil {
		return nil, err
	}
	return group, nil
}

func (m *Authx) RemoveDeviceGroupCredentials(groupCredentials *grpc_device_go.DeviceGroupId) derrors.Error {

	exists, err := m.DeviceProvider.ExistsDeviceGroup(groupCredentials.OrganizationId, groupCredentials.DeviceGroupId)
	if err != nil {
		return err
	}
	if !exists {
		return derrors.NewNotFoundError("device group credentials").WithParams(groupCredentials.OrganizationId, groupCredentials.DeviceGroupId)
	}

	err = m.DeviceProvider.RemoveDeviceGroup(groupCredentials.OrganizationId, groupCredentials.DeviceGroupId)
	if err != nil {
		return err
	}

	return nil
}

func (m *Authx) LoginDeviceGroup(credentials *pbAuthx.DeviceGroupLoginRequest) derrors.Error {

	group, err := m.DeviceProvider.GetDeviceGroupByApiKey(credentials.DeviceGroupApiKey)
	if err != nil {
		return err
	}
	if group.OrganizationID != credentials.OrganizationId {
		return derrors.NewUnauthenticatedError("Invalid credentials")
	}
	// if the group is disabled, the login is not allowed
	if !group.Enabled {
		return derrors.NewPermissionDeniedError("the group is temporarily disabled").WithParams(group.OrganizationID, group.DeviceGroupID)
	}
	return nil

}

// RefreshDeviceToken renew an old token.
func (m *Authx) RefreshDeviceToken(oldToken string, refreshToken string) (*pbAuthx.LoginResponse, derrors.Error) {

	// get the device info
	// 1.- Get the token info
	// 2.- Get the secret
	// 3.- Validate

	dToken, err := m.DeviceTokenProvider.GetByRefreshToken(refreshToken)
	if err != nil {
		return nil, derrors.NewInternalError("error getting token info", err)
	}

	group, err := m.DeviceProvider.GetDeviceGroup(dToken.OrganizationId, dToken.DeviceGroupId)
	if err != nil {
		return nil, err
	}

	claim, err := m.DeviceToken.GetTokenInfo(oldToken, group.Secret)

	// check if the token is correct
	if claim.OrganizationID != dToken.OrganizationId || claim.DeviceGroupID != dToken.DeviceGroupId {
		return nil, derrors.NewUnauthenticatedError("the refresh token is not valid", err)
	}
	// check if the group is enabled
	if !group.Enabled {
		return nil, derrors.NewPermissionDeniedError("the group is temporarily disabled").WithParams(group.OrganizationID, group.DeviceGroupID)
	}

	gToken, err := m.DeviceToken.Refresh(oldToken, refreshToken, m.expirationDuration, group.Secret)
	if err != nil {
		return nil, err
	}
	response := &pbAuthx.LoginResponse{Token: gToken.Token, RefreshToken: gToken.RefreshToken}
	return response, nil
}

// GetDeviceGroupSecret returns secret of the device group
func (m *Authx) GetDeviceGroupSecret(request *grpc_device_go.DeviceGroupId) (*pbAuthx.DeviceGroupSecret, derrors.Error) {

	// get the devicegroup info
	group, err := m.DeviceProvider.GetDeviceGroup(request.OrganizationId, request.DeviceGroupId)
	if err != nil {
		return nil, err
	}
	// returns the secret
	return &pbAuthx.DeviceGroupSecret{
		OrganizationId: group.OrganizationID,
		DeviceGroupId:  group.DeviceGroupID,
		Secret:         group.Secret,
	}, nil

}
