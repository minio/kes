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
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/minio/kes/restapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type PoliciesTestSuite struct {
	suite.Suite
	assert     *assert.Assertions
	testPolicy string
	token      string
	server     *restapi.Server
}

func (suite *PoliciesTestSuite) SetupSuite() {
	suite.assert = assert.New(suite.T())
	suite.testPolicy = "test-policy"
	suite.server, _ = initKESServer()
	suite.assert.NotNil(suite.server)
}

func (suite *PoliciesTestSuite) SetupTest() {
}

func (suite *PoliciesTestSuite) TearDownSuite() {
	suite.server.Shutdown()
}

func (suite *PoliciesTestSuite) TearDownTest() {
}

func (suite *PoliciesTestSuite) TestPolicies() {
	var err error
	suite.token, err = login()
	suite.assert.NoError(err)
	suite.createPolicy()
	suite.listPolicies()
	suite.deletePolicy()
}

func (suite *PoliciesTestSuite) createPolicy() {
	data := map[string]interface{}{"policy": suite.testPolicy, "allow": []string{"*"}}
	res, err := makeRequest(data, "POST", "http://localhost:9393/api/v1/encryption/policies", suite.token)
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	fmt.Println(string(bodyBytes))
	suite.assert.NoError(err)
	suite.assert.Equal(http.StatusOK, res.StatusCode)
}

func (suite *PoliciesTestSuite) listPolicies() {
	res, err := makeRequest(nil, "GET", "http://localhost:9393/api/v1/encryption/policies", suite.token)
	suite.assert.NoError(err)
	suite.assert.Equal(http.StatusOK, res.StatusCode)
}

func (suite *PoliciesTestSuite) deletePolicy() {
	url := fmt.Sprintf("http://localhost:9393/api/v1/encryption/policies/%s", suite.testPolicy)
	res, err := makeRequest(nil, "DELETE", url, suite.token)
	suite.assert.NoError(err)
	suite.assert.Equal(http.StatusOK, res.StatusCode)
}

func TestPolicies(t *testing.T) {
	suite.Run(t, new(PoliciesTestSuite))
}
