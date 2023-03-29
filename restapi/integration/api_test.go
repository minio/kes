// This file is part of MinIO KES
// Copyright (c) 2023 MinIO, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package integration

import (
	"net/http"
	"testing"

	"github.com/minio/kes/restapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type APITestSuite struct {
	suite.Suite
	assert *assert.Assertions
	token  string
	server *restapi.Server
}

func (suite *APITestSuite) SetupSuite() {
	suite.assert = assert.New(suite.T())
	suite.server, _ = initKESServer()
	suite.assert.NotNil(suite.server)
}

func (suite *APITestSuite) SetupTest() {
}

func (suite *APITestSuite) TearDownSuite() {
	suite.server.Shutdown()
}

func (suite *APITestSuite) TearDownTest() {
}

func (suite *APITestSuite) TestAPI() {
	var err error
	suite.token, err = login()
	suite.assert.NoError(err)
	suite.getAPIs()
	suite.getVersion()
	suite.getMetrics()
}

func (suite *APITestSuite) getAPIs() {
	res, err := makeRequest(nil, "GET", "http://localhost:9393/api/v1/encryption/apis", suite.token)
	suite.assert.NoError(err)
	suite.assert.Equal(http.StatusOK, res.StatusCode)
}

func (suite *APITestSuite) getVersion() {
	res, err := makeRequest(nil, "GET", "http://localhost:9393/api/v1/encryption/version", suite.token)
	suite.assert.NoError(err)
	suite.assert.Equal(http.StatusOK, res.StatusCode)
}

func (suite *APITestSuite) getMetrics() {
	res, err := makeRequest(nil, "GET", "http://localhost:9393/api/v1/encryption/metrics", suite.token)
	suite.assert.NoError(err)
	suite.assert.Equal(http.StatusOK, res.StatusCode)
}

func TestAPI(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}
