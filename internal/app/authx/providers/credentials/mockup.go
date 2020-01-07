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

package credentials

import (
	"github.com/nalej/authx/internal/app/authx/entities"
	"github.com/nalej/derrors"
	"sync"
)

// BasicCredentialsMockup is an implementation of this provider only for testing
type BasicCredentialsMockup struct {
	sync.Mutex
	data map[string]entities.BasicCredentialsData
}

// NewBasicCredentialMockup create new mockup.
func NewBasicCredentialMockup() *BasicCredentialsMockup {
	return &BasicCredentialsMockup{data: make(map[string]entities.BasicCredentialsData, 0)}
}

func (p *BasicCredentialsMockup) unsafeGet(username string) (*entities.BasicCredentialsData, derrors.Error) {
	data, ok := p.data[username]
	if !ok {
		return nil, derrors.NewNotFoundError("credentials not found").WithParams(username)
	}
	return &data, nil
}

// Delete remove a specific user credentials.
func (p *BasicCredentialsMockup) Delete(username string) derrors.Error {
	p.Lock()
	defer p.Unlock()
	_, ok := p.data[username]
	if !ok {
		return derrors.NewNotFoundError("username not found").WithParams(username)
	}
	delete(p.data, username)
	return nil
}

// Add adds a new basic credentials.
func (p *BasicCredentialsMockup) Add(credentials *entities.BasicCredentialsData) derrors.Error {
	p.Lock()
	defer p.Unlock()

	p.data[credentials.Username] = *credentials
	return nil
}

// Get recover a user credentials.
func (p *BasicCredentialsMockup) Get(username string) (*entities.BasicCredentialsData, derrors.Error) {
	p.Lock()
	defer p.Unlock()

	data, ok := p.data[username]
	if !ok {
		return nil, derrors.NewNotFoundError("credentials not found").WithParams(username)
	}
	return &data, nil
}

// Exist check if exists a specific credentials.
func (p *BasicCredentialsMockup) Exist(username string) (*bool, derrors.Error) {
	p.Lock()
	defer p.Unlock()

	_, ok := p.data[username]
	return &ok, nil
}

// Edit update a specific user credentials.
func (p *BasicCredentialsMockup) Edit(username string, edit *entities.EditBasicCredentialsData) derrors.Error {
	p.Lock()
	defer p.Unlock()

	data, err := p.unsafeGet(username)
	if err != nil {
		return err
	}
	if edit.RoleID != nil {
		data.RoleID = *edit.RoleID
	}
	if edit.Password != nil {
		data.Password = *edit.Password
	}
	if edit.LastLogin != 0 {
		data.LastLogin = edit.LastLogin
	}

	p.data[username] = *data
	return nil
}

// Truncate removes all credentials.
func (p *BasicCredentialsMockup) Truncate() derrors.Error {
	p.Lock()
	defer p.Unlock()
	p.data = make(map[string]entities.BasicCredentialsData, 0)
	return nil
}
