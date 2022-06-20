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
	"math/big"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffresty"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-evmconnect/internal/jsonrpc"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

type ethConnector struct {
	backend             jsonrpc.Client
	serializer          *abi.Serializer
	gasEstimationFactor *big.Float
}

func NewEthereumConnector(ctx context.Context, conf config.Section) (ffcapi.API, error) {
	c := &ethConnector{}
	if conf.GetString(ffresty.HTTPConfigURL) == "" {
		return nil, i18n.NewError(ctx, msgs.MsgMissingBackendURL)
	}
	c.gasEstimationFactor = big.NewFloat(conf.GetFloat64(ConfigGasEstimationFactor))

	c.backend = jsonrpc.NewRPCClient(ffresty.New(ctx, conf))

	c.serializer = abi.NewSerializer()
	switch conf.Get(ConfigDataFormat) {
	case "map":
		c.serializer.SetFormattingMode(abi.FormatAsObjects)
	case "flat_array":
		c.serializer.SetFormattingMode(abi.FormatAsFlatArrays)
	case "self_describing":
		c.serializer.SetFormattingMode(abi.FormatAsSelfDescribingArrays)
	default:
		return nil, i18n.NewError(ctx, msgs.MsgBadDataFormat, conf.Get(ConfigDataFormat), "map,flat_array,self_describing")
	}

	return c, nil
}
