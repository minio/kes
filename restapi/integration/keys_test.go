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
	"net/http"
	"testing"

	"github.com/minio/kes/restapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type KeysTestSuite struct {
	suite.Suite
	assert  *assert.Assertions
	testKey string
	token   string
	server  *restapi.Server
}

func (suite *KeysTestSuite) SetupSuite() {
	suite.assert = assert.New(suite.T())
	suite.testKey = "test-key"
	suite.server, _ = initKESServer()
	suite.assert.NotNil(suite.server)
}

func (suite *KeysTestSuite) SetupTest() {
}

func (suite *KeysTestSuite) TearDownSuite() {
	suite.server.Shutdown()
}

func (suite *KeysTestSuite) TearDownTest() {
}

func (suite *KeysTestSuite) TestKeys() {
	var err error
	suite.token, err = login()
	suite.assert.NoError(err)
	suite.createKey()
	suite.describeKey()
	suite.listKeys()
	suite.deleteKey()
}

func (suite *KeysTestSuite) createKey() {
	data := map[string]interface{}{"key": suite.testKey}
	res, err := makeRequest(data, "POST", "http://localhost:9393/api/v1/encryption/keys", suite.token)
	suite.assert.NoError(err)
	suite.assert.Equal(http.StatusCreated, res.StatusCode)
}

func (suite *KeysTestSuite) describeKey() {
	url := fmt.Sprintf("http://localhost:9393/api/v1/encryption/keys/%s", suite.testKey)
	res, err := makeRequest(nil, "GET", url, suite.token)
	suite.assert.NoError(err)
	suite.assert.Equal(http.StatusOK, res.StatusCode)
}

func (suite *KeysTestSuite) listKeys() {
	res, err := makeRequest(nil, "GET", "http://localhost:9393/api/v1/encryption/keys", suite.token)
	suite.assert.NoError(err)
	suite.assert.Equal(http.StatusOK, res.StatusCode)
}

func (suite *KeysTestSuite) deleteKey() {
	url := fmt.Sprintf("http://localhost:9393/api/v1/encryption/keys/%s", suite.testKey)
	res, err := makeRequest(nil, "DELETE", url, suite.token)
	suite.assert.NoError(err)
	suite.assert.Equal(http.StatusOK, res.StatusCode)
}

func TestKeys(t *testing.T) {
	suite.Run(t, new(KeysTestSuite))
}
