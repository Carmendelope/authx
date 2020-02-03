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

package certificates_monitoring

import (
	"github.com/nalej/authx/internal/app/authx/utils"
	"github.com/onsi/ginkgo"
	"github.com/rs/zerolog/log"
	"os"
	"strconv"
)

/*
docker run --name scylla -p 9042:9042 -d scylladb/scylla
docker exec -it scylla nodetool status
docker exec -it scylla cqlsh

create KEYSPACE authx WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

create table IF NOT EXISTS authx.certificates_monitoring
(
    organization_id      text,
    certificate_id       text,
    creation_timestamp   bigint,
    expiration_timestamp bigint,
    revocation_timestamp bigint,
    PRIMARY KEY (organization_id, certificate_id)
);

Environment variables
IT_SCYLLA_HOST=127.0.0.1
RUN_INTEGRATION_TEST=true
IT_NALEJ_KEYSPACE=nalej
IT_SCYLLA_PORT=9042

*/
var _ = ginkgo.Describe("CertificatesMonitoringScylla", func() {

	if !utils.RunIntegrationTests() {
		log.Warn().Msg("Integration tests are skipped")
		return
	}

	var scyllaHost = os.Getenv("IT_SCYLLA_HOST")
	if scyllaHost == "" {
		ginkgo.Fail("missing environment variables")
	}

	scyllaPort, _ := strconv.Atoi(os.Getenv("IT_SCYLLA_PORT"))

	if scyllaPort <= 0 {
		ginkgo.Fail("missing environment variables")
	}

	var nalejKeySpace = os.Getenv("IT_NALEJ_KEYSPACE")
	if nalejKeySpace == "" {
		ginkgo.Fail("missing environment variables")
	}

	// create a provider and connect it
	sp := NewCertificatesMonitoringScyllaProvider(scyllaHost, scyllaPort, nalejKeySpace)

	// disconnect
	ginkgo.AfterSuite(func() {
		sp.Disconnect()
	})

	CertificatesMonitoringTests(sp)
})
