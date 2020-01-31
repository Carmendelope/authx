/*
 * Copyright 2020 Nalej
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
 */

package certificates_monitoring

import (
	"github.com/nalej/authx/internal/app/authx/entities"
	"github.com/nalej/derrors"
	"github.com/nalej/scylladb-utils/pkg/scylladb"
	"github.com/scylladb/gocqlx"
	"github.com/scylladb/gocqlx/qb"
	"sync"
	"time"
)

type MonitoringCertificatesScyllaProvider struct {
	sync.Mutex
	scylladb.ScyllaDB
}

func NewMonitoringCertificatesScyllaProvider(address string, port int, keySpace string) *MonitoringCertificatesScyllaProvider {
	provider := MonitoringCertificatesScyllaProvider{
		ScyllaDB: scylladb.ScyllaDB{
			Address:  address,
			Port:     port,
			Keyspace: keySpace,
		},
	}
	_ = provider.Connect()
	return &provider
}

func (sp *MonitoringCertificatesScyllaProvider) Disconnect() {
	sp.Lock()
	defer sp.Unlock()
	sp.ScyllaDB.Disconnect()
}

// --------------------------------------------------------------------------------------------------------------------
const table = "certificates_monitoring"

var columns = []string{
	"organization_id",
	"certificate_id",
	"creation_timestamp",
	"expiration_timestamp",
	"revocation_timestamp",
}
var updateableColumns = []string{
	"revocation_timestamp",
}

func (sp *MonitoringCertificatesScyllaProvider) createPkMap(organizationId string, certificateId string) map[string]interface{} {
	return map[string]interface{}{
		"organization_id": organizationId,
		"certificate_id":  certificateId,
	}
}

// --------------------------------------------------------------------------------------------------------------------
func (sp *MonitoringCertificatesScyllaProvider) Add(certificate *entities.MonitoringCertificate) derrors.Error {
	sp.Lock()
	defer sp.Unlock()
	pkComposite := sp.createPkMap(certificate.OrganizationId, certificate.CertificateId)
	return sp.UnsafeCompositeAdd(table, pkComposite, columns, certificate)
}

func (sp *MonitoringCertificatesScyllaProvider) Get(organizationId string, certificateId string) (*entities.MonitoringCertificate, derrors.Error) {
	sp.Lock()
	defer sp.Unlock()
	pkComposite := sp.createPkMap(organizationId, certificateId)
	result := interface{}(&entities.MonitoringCertificate{})
	if err := sp.UnsafeCompositeGet(table, pkComposite, columns, &result); err != nil {
		return nil, err
	}
	return result.(*entities.MonitoringCertificate), nil
}

func (sp *MonitoringCertificatesScyllaProvider) List(organizationId string) ([]*entities.MonitoringCertificate, derrors.Error) {
	sp.Lock()
	defer sp.Unlock()

	if err := sp.CheckAndConnect(); err != nil {
		return nil, err
	}

	filterColumn := "organization_id"
	stmt, names := qb.Select(table).Columns(columns...).Where(qb.Eq(filterColumn)).ToCql()
	q := gocqlx.Query(sp.Session.Query(stmt), names).BindMap(qb.M{
		filterColumn: organizationId,
	})

	connections := make([]*entities.MonitoringCertificate, 0)
	if qerr := q.SelectRelease(&connections); qerr != nil {
		return nil, derrors.AsError(qerr, "cannot list monitoring certificates")
	}

	return connections, nil
}

func (sp *MonitoringCertificatesScyllaProvider) Revoke(organizationId string, certificateId string) derrors.Error {
	sp.Lock()
	defer sp.Unlock()
	revoked := entities.MonitoringCertificate{
		OrganizationId:      organizationId,
		CertificateId:       certificateId,
		RevocationTimestamp: time.Now().UnixNano(),
	}
	pkComposite := sp.createPkMap(organizationId, certificateId)
	return sp.UnsafeCompositeUpdate(table, pkComposite, updateableColumns, revoked)
}

func (sp *MonitoringCertificatesScyllaProvider) Truncate() derrors.Error {
	sp.Lock()
	defer sp.Unlock()
	return sp.UnsafeClear([]string{table})
}
