// Copyright © 2022 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ffcserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/httpserver"
	"github.com/hyperledger/firefly-evmconnect/internal/ffconnector"
	"github.com/hyperledger/firefly-evmconnect/mocks/ffconnectormocks"
	"github.com/stretchr/testify/assert"
)

func newTestFFCAPIServer(t *testing.T) (*ffcServer, func()) {
	config.RootConfigReset()
	conf := config.RootSection("unittest")
	InitConfig(conf, conf)
	mConn := &ffconnectormocks.Connector{}
	mConn.On("HandlerMap").Return(map[ffcapi.RequestType]ffconnector.FFCHandler{})
	s := NewServer(conf, mConn).(*ffcServer)
	conf.Set(httpserver.HTTPConfPort, 0)
	err := s.Init(context.Background(), conf, conf)
	assert.NoError(t, err)
	s.Start()
	return s, func() {
		s.RequestStop()
		err := s.WaitStopped()
		assert.NoError(t, err)
	}
}

func TestServerInitFail(t *testing.T) {
	config.RootConfigReset()
	conf := config.RootSection("unittest")
	InitConfig(conf, conf)
	mConn := &ffconnectormocks.Connector{}
	mConn.On("HandlerMap").Return(map[ffcapi.RequestType]ffconnector.FFCHandler{})
	s := NewServer(conf, mConn).(*ffcServer)
	conf.Set(httpserver.HTTPConfAddress, ":::::")
	err := s.Init(context.Background(), conf, conf)
	assert.Regexp(t, "FF00151", err)
}

func TestServerStartNotInitialized(t *testing.T) {
	config.RootConfigReset()
	conf := config.RootSection("unittest")
	mConn := &ffconnectormocks.Connector{}
	mConn.On("HandlerMap").Return(map[ffcapi.RequestType]ffconnector.FFCHandler{})
	s := NewServer(conf, mConn).(*ffcServer)
	err := s.Start()
	assert.Regexp(t, "FF23024", err)
}

func TestServerStartStop(t *testing.T) {

	s, done := newTestFFCAPIServer(t)

	// Double start should be a no-op
	s.Start()

	done()
}

func TestServerBadVersion(t *testing.T) {

	s, done := newTestFFCAPIServer(t)
	defer done()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
		"ffcapi": {
			"version": "not a sem ver"
		}
	}`))
	s.serveFFCAPI(recorder, req)

	assert.Equal(t, 400, recorder.Result().StatusCode)
	var errRes ffcapi.ErrorResponse
	err := json.NewDecoder(recorder.Body).Decode(&errRes)
	assert.NoError(t, err)
	assert.Regexp(t, "FF23026", errRes.Error)
	assert.Regexp(t, ffcapi.ErrorReasonInvalidInputs, errRes.Reason)

}

func TestServerIncompatibleVersion(t *testing.T) {

	s, done := newTestFFCAPIServer(t)
	defer done()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
		"ffcapi": {
			"version": "v99.0.0"
		}
	}`))
	s.serveFFCAPI(recorder, req)

	assert.Equal(t, 400, recorder.Result().StatusCode)
	var errRes ffcapi.ErrorResponse
	err := json.NewDecoder(recorder.Body).Decode(&errRes)
	assert.NoError(t, err)
	assert.Regexp(t, "FF23027", errRes.Error)
	assert.Regexp(t, ffcapi.ErrorReasonInvalidInputs, errRes.Reason)

}

func TestServerMissingID(t *testing.T) {

	s, done := newTestFFCAPIServer(t)
	defer done()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
		"ffcapi": {
			"version": "v1.0.1"
		}
	}`))
	s.serveFFCAPI(recorder, req)

	assert.Equal(t, 400, recorder.Result().StatusCode)
	var errRes ffcapi.ErrorResponse
	err := json.NewDecoder(recorder.Body).Decode(&errRes)
	assert.NoError(t, err)
	assert.Regexp(t, "FF23029", errRes.Error)
	assert.Regexp(t, ffcapi.ErrorReasonInvalidInputs, errRes.Reason)

}

func TestServerUnknownRequestType(t *testing.T) {

	s, done := newTestFFCAPIServer(t)
	defer done()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
		"ffcapi": {
			"version": "v1.0.1",
			"id": "`+fftypes.NewUUID().String()+`",
			"type": "test"
		}
	}`))
	s.serveFFCAPI(recorder, req)

	assert.Equal(t, 400, recorder.Result().StatusCode)
	var errRes ffcapi.ErrorResponse
	err := json.NewDecoder(recorder.Body).Decode(&errRes)
	assert.NoError(t, err)
	assert.Regexp(t, "FF23028", errRes.Error)
	assert.Regexp(t, ffcapi.ErrorReasonInvalidInputs, errRes.Reason)

}

func TestServerUnknownRequestOK(t *testing.T) {

	s, done := newTestFFCAPIServer(t)
	defer done()
	s.handlerMap[ffcapi.RequestType("test")] = func(ctx context.Context, payload []byte) (res interface{}, reason ffcapi.ErrorReason, err error) {
		return map[string]interface{}{
			"test": "data",
		}, "", nil
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
		"ffcapi": {
			"version": "v1.0.1",
			"id": "`+fftypes.NewUUID().String()+`",
			"type": "test"
		}
	}`))
	s.serveFFCAPI(recorder, req)

	assert.Equal(t, 200, recorder.Result().StatusCode)
	var mapRes map[string]interface{}
	err := json.NewDecoder(recorder.Body).Decode(&mapRes)
	assert.NoError(t, err)
	assert.Regexp(t, "data", mapRes["test"])

}

func TestMapReasonStatus(t *testing.T) {
	s, done := newTestFFCAPIServer(t)
	defer done()
	assert.Equal(t, 404, s.mapReasonStatus(ffcapi.ErrorReasonNotFound))
	assert.Equal(t, 400, s.mapReasonStatus(ffcapi.ErrorReasonInvalidInputs))
	assert.Equal(t, 500, s.mapReasonStatus(""))
}
