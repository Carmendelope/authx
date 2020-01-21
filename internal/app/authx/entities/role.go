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

import "github.com/nalej/grpc-authx-go"

// RoleData is the structure that is stored in the provider.
type RoleData struct {
	OrganizationID string
	RoleID         string
	Name           string
	Internal       bool
	Primitives     []string
}

// NewRoleData create a new instance of the structure.
func NewRoleData(organizationID string, roleID string, name string, internal bool, primitives []string) *RoleData {
	return &RoleData{
		OrganizationID: organizationID,
		RoleID:         roleID,
		Name:           name,
		Internal:       internal,
		Primitives:     primitives,
	}
}

// UserAuthxInfo contains information about an authx user
type UserAuthxInfo struct {
	OrganizationID string
	RoleID         string
	RoleName       string
	InternalRole   bool
	Primitives     []string
	LastLogin      int64
}

// NewUserAuthxInfo creates a new instance of the structure.
func NewUserAuthxInfo(organizationID string, roleId string, roleName string, internalRole bool, primitives []string, lastLogin int64) *UserAuthxInfo {
	return &UserAuthxInfo{
		OrganizationID: organizationID,
		RoleID:         roleId,
		RoleName:       roleName,
		InternalRole:   internalRole,
		Primitives:     primitives,
		LastLogin:      lastLogin,
	}
}

func PrimitiveToGRPC(name string) grpc_authx_go.AccessPrimitive {
	switch name {
	case grpc_authx_go.AccessPrimitive_ORG.String():
		return grpc_authx_go.AccessPrimitive_ORG
	case grpc_authx_go.AccessPrimitive_APPS.String():
		return grpc_authx_go.AccessPrimitive_APPS
	case grpc_authx_go.AccessPrimitive_RESOURCES.String():
		return grpc_authx_go.AccessPrimitive_RESOURCES
	case grpc_authx_go.AccessPrimitive_PROFILE.String():
		return grpc_authx_go.AccessPrimitive_PROFILE
	case grpc_authx_go.AccessPrimitive_APPCLUSTEROPS.String():
		return grpc_authx_go.AccessPrimitive_APPCLUSTEROPS
	case grpc_authx_go.AccessPrimitive_ORG_MNGT.String():
		return grpc_authx_go.AccessPrimitive_ORG_MNGT
	case grpc_authx_go.AccessPrimitive_RESOURCES_MNGT.String():
		return grpc_authx_go.AccessPrimitive_RESOURCES_MNGT
	}
	panic("access primitive not found")
}

func (r *RoleData) ToGRPC() *grpc_authx_go.Role {
	primitives := make([]grpc_authx_go.AccessPrimitive, 0)
	for _, p := range r.Primitives {
		primitives = append(primitives, PrimitiveToGRPC(p))
	}
	return &grpc_authx_go.Role{
		OrganizationId: r.OrganizationID,
		RoleId:         r.RoleID,
		Name:           r.Name,
		Internal:       r.Internal,
		Primitives:     primitives,
	}
}

// EditRoleData is the structure that is used to edit the data in the provider.
type EditRoleData struct {
	Name       *string
	Primitives *[]string
}

//WithName update the name of the role.
func (d *EditRoleData) WithName(name string) *EditRoleData {
	d.Name = &name
	return d
}

//WithPrimitives update the primitives.
func (d *EditRoleData) WithPrimitives(primitives []string) *EditRoleData {
	d.Primitives = &primitives
	return d
}

//NewEditRoleData create a new instance of the structure.
func NewEditRoleData() *EditRoleData {
	return &EditRoleData{}
}
