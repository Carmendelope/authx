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

// BasicCredentialsData is the struct that is store in the database.
type BasicCredentialsData struct {
	// Username is the credential id.
	Username string
	// Password is the user defined password.
	Password []byte
	// RoleID is the assigned role.
	RoleID string
	// OrganizationID is the assigned organization.
	OrganizationID string
	// LastLogin is the timestamp of the last login of a user
	LastLogin int64
}

// NewBasicCredentialsData creates an instance of BasicCredentialsData.
func NewBasicCredentialsData(username string, password []byte, roleID string, organizationID string) *BasicCredentialsData {
	return &BasicCredentialsData{
		Username:       username,
		Password:       password,
		RoleID:         roleID,
		OrganizationID: organizationID,
	}
}

// EditBasicCredentialsData is an object that allows to edit the credentials record.
type EditBasicCredentialsData struct {
	Password  *[]byte
	RoleID    *string
	LastLogin int64
}

// WithPassword allows to change the password.
func (d *EditBasicCredentialsData) WithPassword(password []byte) *EditBasicCredentialsData {
	d.Password = &password
	return d
}

// WithRoleID allows to change the roleID
func (d *EditBasicCredentialsData) WithRoleID(roleID string) *EditBasicCredentialsData {
	d.RoleID = &roleID
	return d
}

// NewEditBasicCredentialsData create a new instance of EditBasicCredentialsData.
func NewEditBasicCredentialsData() *EditBasicCredentialsData {
	return &EditBasicCredentialsData{}
}
