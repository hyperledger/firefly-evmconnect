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
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/Masterminds/semver"
	"github.com/gorilla/mux"
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-common/pkg/httpserver"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/ffconnector"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
)

type Server interface {
	Init(ctx context.Context, conf, corsConf config.Section) error
	Start() error
	RequestStop()
	WaitStopped() error
}

var supportedAPIVersions = "1.0.x"

type ffcServer struct {
	ctx        context.Context
	cancelCtx  func()
	connector  ffconnector.Connector
	handlerMap map[ffcapi.RequestType]ffconnector.FFCHandler

	started       bool
	apiServer     httpserver.HTTPServer
	apiServerDone chan error
	versionCheck  *semver.Constraints
}

// NewServer performs static initialization. You must still call Init() before Start().
func NewServer(conf config.Section, connector ffconnector.Connector) Server {
	s := &ffcServer{
		connector: connector,
	}
	s.handlerMap = connector.HandlerMap()
	return s
}

// Init verifies the configuration values (distinct from InitConfig which simply initializes
//     what configuration is allowed to be set).
func (s *ffcServer) Init(ctx context.Context, conf, corsConf config.Section) (err error) {
	s.ctx, s.cancelCtx = context.WithCancel(ctx)

	s.apiServerDone = make(chan error)
	s.apiServer, err = httpserver.NewHTTPServer(s.ctx, "server", s.router(), s.apiServerDone, conf, corsConf)
	if err != nil {
		return err
	}

	s.versionCheck, _ = semver.NewConstraint(supportedAPIVersions)

	return err
}

func (s *ffcServer) runAPIServer() {
	s.apiServer.ServeHTTP(s.ctx)
}

func (s *ffcServer) Start() error {
	if s.cancelCtx == nil {
		return i18n.NewError(context.Background(), msgs.MsgNotInitialized)
	}
	if s.started {
		return nil
	}
	go s.runAPIServer()
	s.started = true
	return nil
}

func (s *ffcServer) RequestStop() {
	if s.cancelCtx != nil {
		s.cancelCtx()
	}
}

func (s *ffcServer) WaitStopped() (err error) {
	if s.started {
		err = <-s.apiServerDone
		s.started = false
	}
	return err
}

func (s *ffcServer) router() *mux.Router {
	mux := mux.NewRouter()
	mux.Path("/").Methods(http.MethodPost).Handler(http.HandlerFunc(s.serveFFCAPI))
	return mux
}

func (s *ffcServer) serveFFCAPI(res http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	var resBody interface{}
	status := 200
	reason := ffcapi.ErrorReasonInvalidInputs
	payload, err := ioutil.ReadAll(req.Body)
	if err == nil {
		var resBase ffcapi.RequestBase
		var handler ffconnector.FFCHandler
		_ = json.Unmarshal(payload, &resBase)
		handler, err = s.validateHeader(ctx, &resBase.FFCAPI)
		if err == nil {
			log.L(ctx).Tracef("--> %s %s", resBase.FFCAPI.RequestType, payload)
			resBody, reason, err = handler(ctx, payload)
			log.L(ctx).Tracef("<-- %s %s %v", resBase.FFCAPI.RequestType, reason, err)
		}
	}
	if err != nil {
		log.L(ctx).Errorf("Request failed: %s", err)
		resBody = &ffcapi.ErrorResponse{Error: err.Error(), Reason: reason}
		status = s.mapReasonStatus(reason)
	}
	res.Header().Set("Content-Type", "application/json")
	resBytes, _ := json.Marshal(resBody)
	res.Header().Set("Content-Length", strconv.FormatInt(int64(len(resBytes)), 10))
	res.WriteHeader(status)
	_, _ = res.Write(resBytes)
}

func (s *ffcServer) mapReasonStatus(reason ffcapi.ErrorReason) int {
	switch reason {
	case ffcapi.ErrorReasonNotFound:
		return http.StatusNotFound
	case ffcapi.ErrorReasonInvalidInputs:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func (s *ffcServer) validateHeader(ctx context.Context, header *ffcapi.Header) (ffconnector.FFCHandler, error) {
	v, err := semver.NewVersion(string(header.Version))
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgBadVersion, header.Version, err)
	}
	if !s.versionCheck.Check(v) {
		return nil, i18n.NewError(ctx, msgs.MsgUnsupportedVersion, header.Version)
	}
	if header.RequestID == nil {
		return nil, i18n.NewError(ctx, msgs.MsgMissingRequestID)
	}
	handler, ok := s.handlerMap[header.RequestType]
	if !ok {
		return nil, i18n.NewError(ctx, msgs.MsgUnsupportedRequestType, header.RequestType)
	}
	return handler, nil
}
