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

package ethereum

import (
	"context"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffresty"
	"github.com/hyperledger/firefly-evmconnect/mocks/jsonrpcmocks"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/stretchr/testify/assert"
)

func newTestConnector(t *testing.T) (context.Context, func(), *ethConnector, *jsonrpcmocks.Client) {

	mRPC := &jsonrpcmocks.Client{}
	config.RootConfigReset()
	conf := config.RootSection("unittest")
	InitConfig(conf)
	conf.Set(ffresty.HTTPConfigURL, "http://localhost:8545")
	conf.Set(BlockPollingInterval, "1h") // Disable for tests that are not using it
	ctx, done := context.WithCancel(context.Background())
	cc, err := NewEthereumConnector(ctx, conf)
	assert.NoError(t, err)
	c := cc.(*ethConnector)
	c.backend = mRPC
	return ctx, done, c, mRPC

}

func TestConnectorInit(t *testing.T) {

	config.RootConfigReset()
	conf := config.RootSection("unittest")
	InitConfig(conf)

	cc, err := NewEthereumConnector(context.Background(), conf)
	assert.Regexp(t, "FF23025", err)

	conf.Set(ffresty.HTTPConfigURL, "http://localhost:8545")

	cc, err = NewEthereumConnector(context.Background(), conf)
	assert.NoError(t, err)

	params := &abi.ParameterArray{
		{Name: "x", Type: "uint256"},
		{Name: "y", Type: "uint256"},
	}
	cv, err := params.ParseJSON([]byte(`{"x":12345,"y":23456}`))
	assert.NoError(t, err)

	conf.Set(ConfigDataFormat, "map")
	cc, err = NewEthereumConnector(context.Background(), conf)
	assert.NoError(t, err)
	jv, err := cc.(*ethConnector).serializer.SerializeJSON(cv)
	assert.NoError(t, err)
	assert.JSONEq(t, `{"x":"12345","y":"23456"}`, string(jv))

	conf.Set(ConfigDataFormat, "flat_array")
	cc, err = NewEthereumConnector(context.Background(), conf)
	assert.NoError(t, err)
	jv, err = cc.(*ethConnector).serializer.SerializeJSON(cv)
	assert.NoError(t, err)
	assert.JSONEq(t, `["12345","23456"]`, string(jv))

	conf.Set(ConfigDataFormat, "self_describing")
	cc, err = NewEthereumConnector(context.Background(), conf)
	assert.NoError(t, err)
	jv, err = cc.(*ethConnector).serializer.SerializeJSON(cv)
	assert.NoError(t, err)
	assert.JSONEq(t, `[{"name":"x","type":"uint256","value":"12345"},{"name":"y","type":"uint256","value":"23456"}]`, string(jv))

	conf.Set(ConfigDataFormat, "wrong")
	cc, err = NewEthereumConnector(context.Background(), conf)
	assert.Regexp(t, "FF23032.*wrong", err)

}
