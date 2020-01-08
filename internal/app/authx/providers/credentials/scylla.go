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
	"github.com/gocql/gocql"
	"github.com/nalej/authx/internal/app/authx/entities"
	"github.com/nalej/derrors"
	"github.com/nalej/grpc-utils/pkg/conversions"
	"github.com/rs/zerolog/log"
	"github.com/scylladb/gocqlx"
	"github.com/scylladb/gocqlx/qb"
	"sync"
)

const table = "credentials"
const tablePK = "username"

const rowNotFound = "not found"

type ScyllaCredentialsProvider struct {
	Address  string
	Port     int
	KeySpace string
	sync.Mutex
	Session *gocql.Session
}

func NewScyllaCredentialsProvider(address string, port int, keyspace string) *ScyllaCredentialsProvider {
	provider := ScyllaCredentialsProvider{Address: address, Port: port, KeySpace: keyspace}
	provider.connect()
	return &provider
}

func (sp *ScyllaCredentialsProvider) connect() derrors.Error {

	// connect to the cluster
	conf := gocql.NewCluster(sp.Address)
	conf.Keyspace = sp.KeySpace
	conf.Port = sp.Port

	session, err := conf.CreateSession()
	if err != nil {
		log.Error().Str("provider", "ScyllaCredentialsProvider").Str("trace", conversions.ToDerror(err).DebugReport()).Msg("unable to connect")
		return derrors.AsError(err, "cannot create session")
	}

	sp.Session = session
	return nil
}

func (sp *ScyllaCredentialsProvider) Disconnect() {

	sp.Lock()
	defer sp.Unlock()

	if sp.Session != nil {
		sp.Session.Close()
		sp.Session = nil
	}
}

func (sp *ScyllaCredentialsProvider) checkConnectionAndConnect() derrors.Error {

	if sp.Session != nil {
		return nil
	}
	log.Info().Str("provider", "ScyllaCredentialsProvider").Msg("session not connected, trying to connect it!")
	err := sp.connect()
	if err != nil {
		return derrors.AsError(err, "cannot connect")
	}

	return nil
}

// --------------------------------------------------------------------------------------------------------------------
func (sp *ScyllaCredentialsProvider) unsafeGet(username string) (*entities.BasicCredentialsData, derrors.Error) {

	var credentials entities.BasicCredentialsData
	stmt, names := qb.Select(table).Where(qb.Eq(tablePK)).ToCql()
	q := gocqlx.Query(sp.Session.Query(stmt), names).BindMap(qb.M{
		tablePK: username,
	})

	err := q.GetRelease(&credentials)
	if err != nil {
		if err.Error() == rowNotFound {
			return nil, derrors.NewNotFoundError(username)
		} else {
			return nil, derrors.AsError(err, "cannot get credentials")
		}
	}

	return &credentials, nil
}

func (sp *ScyllaCredentialsProvider) unsafeExist(username string) (*bool, derrors.Error) {
	var returnedEmail string

	ok := false

	stmt, names := qb.Select(table).Columns(tablePK).Where(qb.Eq(tablePK)).ToCql()
	q := gocqlx.Query(sp.Session.Query(stmt), names).BindMap(qb.M{
		tablePK: username})

	err := q.GetRelease(&returnedEmail)
	if err != nil {
		if err.Error() == rowNotFound {
			return &ok, nil
		} else {
			return &ok, derrors.AsError(err, "cannot determine if credentials exists")
		}
	}

	ok = true
	return &ok, nil
}

// --------------------------------------------------------------------------------------------------------------------

// Delete remove a specific user credentials.
func (sp *ScyllaCredentialsProvider) Delete(username string) derrors.Error {

	sp.Lock()
	defer sp.Unlock()

	// check connection
	if err := sp.checkConnectionAndConnect(); err != nil {
		return err
	}

	// check if the user credentials exists
	exists, err := sp.unsafeExist(username)

	if err != nil {
		return err
	}
	if !*exists {
		return derrors.NewNotFoundError("credentials").WithParams(username)
	}

	// remove a user credentials
	stmt, _ := qb.Delete(table).Where(qb.Eq(tablePK)).ToCql()
	cqlErr := sp.Session.Query(stmt, username).Exec()

	if cqlErr != nil {
		return derrors.AsError(cqlErr, "cannot delete credentials")
	}

	return nil
}

// Add adds a new basic credentials.
func (sp *ScyllaCredentialsProvider) Add(credentials *entities.BasicCredentialsData) derrors.Error {

	sp.Lock()
	defer sp.Unlock()

	if err := sp.checkConnectionAndConnect(); err != nil {
		return err
	}

	exists, err := sp.unsafeExist(credentials.Username)
	if err != nil {
		return err
	}
	if *exists {
		return derrors.NewAlreadyExistsError("credentials").WithParams(credentials.Username)
	}

	// add new basic credential
	stmt, names := qb.Insert(table).Columns("username", "password", "role_id", "organization_id", "last_login").ToCql()
	q := gocqlx.Query(sp.Session.Query(stmt), names).BindStruct(credentials)
	cqlErr := q.ExecRelease()

	if cqlErr != nil {
		return derrors.AsError(cqlErr, "cannot add credentials")
	}

	return nil
}

// Get recover a user credentials.
func (sp *ScyllaCredentialsProvider) Get(username string) (*entities.BasicCredentialsData, derrors.Error) {

	sp.Lock()
	defer sp.Unlock()

	if err := sp.checkConnectionAndConnect(); err != nil {
		return nil, err
	}

	var credentials entities.BasicCredentialsData
	stmt, names := qb.Select(table).Where(qb.Eq(tablePK)).ToCql()
	q := gocqlx.Query(sp.Session.Query(stmt), names).BindMap(qb.M{
		tablePK: username,
	})

	err := q.GetRelease(&credentials)
	if err != nil {
		if err.Error() == rowNotFound {
			return nil, derrors.NewNotFoundError(username)
		} else {
			return nil, derrors.AsError(err, "cannot get credentials")
		}
	}

	return &credentials, nil
}

// Edit update a specific user credentials.
func (sp *ScyllaCredentialsProvider) Edit(username string, edit *entities.EditBasicCredentialsData) derrors.Error {

	sp.Lock()
	defer sp.Unlock()

	if err := sp.checkConnectionAndConnect(); err != nil {
		return err
	}

	data, err := sp.unsafeGet(username)

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

	// update
	stmt, names := qb.Update(table).Set("password", "role_id", "organization_id", "last_login").Where(qb.Eq(tablePK)).ToCql()
	q := gocqlx.Query(sp.Session.Query(stmt), names).BindStruct(data)
	cqlErr := q.ExecRelease()


	if cqlErr != nil {
		return derrors.AsError(cqlErr, "cannot update credentials")
	}

	return nil

}

// Exist check if exists a specific credentials.
func (sp *ScyllaCredentialsProvider) Exist(username string) (*bool, derrors.Error) {

	var returnedEmail string
	ok := false

	sp.Lock()
	defer sp.Unlock()

	// check connection
	if err := sp.checkConnectionAndConnect(); err != nil {
		return &ok, err
	}

	stmt, names := qb.Select(table).Columns(tablePK).Where(qb.Eq(tablePK)).ToCql()
	q := gocqlx.Query(sp.Session.Query(stmt), names).BindMap(qb.M{
		tablePK: username})

	err := q.GetRelease(&returnedEmail)
	if err != nil {
		if err.Error() == rowNotFound {
			return &ok, nil
		} else {
			return &ok, derrors.AsError(err, "cannot determine if credentials exists")
		}
	}

	ok = true
	return &ok, nil
}

// Truncate removes all credentials.
func (sp *ScyllaCredentialsProvider) Truncate() derrors.Error {

	sp.Lock()
	defer sp.Unlock()

	if err := sp.checkConnectionAndConnect(); err != nil {
		return err
	}

	err := sp.Session.Query("TRUNCATE TABLE credentials").Exec()
	if err != nil {
		log.Info().Str("trace", conversions.ToDerror(err).DebugReport()).Msg("failed to truncate the table")
		return derrors.AsError(err, "cannot truncate credentials table")
	}

	return nil
}
