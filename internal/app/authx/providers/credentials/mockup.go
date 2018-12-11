package credentials

import (
	"github.com/nalej/authx/internal/app/authx/entities"
	"github.com/nalej/derrors"
)


// BasicCredentialsMockup is an implementation of this provider only for testing
type BasicCredentialsMockup struct {
	data map[string]entities.BasicCredentialsData
}

// NewBasicCredentialMockup create new mockup.
func NewBasicCredentialMockup() *BasicCredentialsMockup {
	return &BasicCredentialsMockup{data: make(map[string]entities.BasicCredentialsData, 0)}
}

// Delete remove a specific user credentials.
func (p *BasicCredentialsMockup) Delete(username string) derrors.Error {
	_, ok := p.data[username]
	if !ok {
		return derrors.NewNotFoundError("username not found").WithParams(username)
	}
	delete(p.data, username)
	return nil
}

// Add adds a new basic credentials.
func (p *BasicCredentialsMockup) Add(credentials *entities.BasicCredentialsData) derrors.Error {
	p.data[credentials.Username] = *credentials
	return nil
}

// Get recover a user credentials.
func (p *BasicCredentialsMockup) Get(username string) (*entities.BasicCredentialsData, derrors.Error) {
	data, ok := p.data[username]
	if !ok {
		return nil, derrors.NewNotFoundError("credentials not found").WithParams(username)
	}
	return &data, nil
}

// Exist check if exists a specific credentials.
func (p *BasicCredentialsMockup) Exist(username string) (*bool,derrors.Error){
	_, ok := p.data[username]
	return &ok,nil
}

// Edit update a specific user credentials.
func (p *BasicCredentialsMockup) Edit(username string, edit *entities.EditBasicCredentialsData) derrors.Error {
	data, err := p.Get(username)
	if err != nil {
		return err
	}
	if edit.RoleID != nil {
		data.RoleID = *edit.RoleID
	}
	if edit.Password != nil {
		data.Password = *edit.Password
	}
	p.data[username] = *data
	return nil
}

// Truncate removes all credentials.
func (p *BasicCredentialsMockup) Truncate() derrors.Error {
	p.data = make(map[string]entities.BasicCredentialsData, 0)
	return nil
}