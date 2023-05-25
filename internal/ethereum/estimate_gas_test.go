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
	"encoding/json"
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const sampleGasEstimate = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "get_address_balance"
	},
	"to": "0x4a8c8f1717570f9774652075e249ded38124d708",
	"from": "0x73bd8f17787a0f9774652075e2ba5ed381246bef",
	"value": "100000000",
	"nonce": "0x01"
}`

func TestGasEstimateOK(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_estimateGas",
		mock.MatchedBy(func(tx *ethsigner.Transaction) bool {
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			args[1].(*ethtypes.HexInteger).BigInt().SetString("12345", 10)
		})

	var req ffcapi.TransactionInput
	err := json.Unmarshal([]byte(sampleGasEstimate), &req)
	assert.NoError(t, err)
	res, reason, err := c.GasEstimate(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)

	assert.Equal(t, int64(18517) /* 1.5 uplift */, res.GasEstimate.Int64())

}

func TestGasEstimateFail(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_estimateGas",
		mock.MatchedBy(func(tx *ethsigner.Transaction) bool {
			return true
		})).
		Return(&rpcbackend.RPCError{Message: "pop"})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").Run(
		func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x08c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000114d75707065747279206465746563746564000000000000000000000000000000")
		},
	).Return(nil)

	var req ffcapi.TransactionInput
	err := json.Unmarshal([]byte(sampleGasEstimate), &req)
	assert.NoError(t, err)
	res, reason, err := c.GasEstimate(ctx, &req)
	assert.Regexp(t, "FF23021", err)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	assert.Nil(t, res)

}
