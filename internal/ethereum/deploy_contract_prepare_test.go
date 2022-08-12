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
	"fmt"
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const samplePrepareDeployTX = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "DeployContract"
	},
	"from": "0xb480F96c0a3d6E9e9a263e4665a39bFa6c4d01E8",
	"to": "0xe1a078b9e2b145d0a7387f09277c6ae1d9470771",
	"gas": 1000000,
	"nonce": "111",
	"value": "12345678901234567890123456789",
	"contract": "0xfeedbeef",
	"definition": [{
		"inputs": [
			{
				"internalType":" uint256",
				"name": "x",
				"type": "uint256"
			}
		],
		"outputs":[],
		"type":"constructor"
	}],
	"params": [ 4276993775 ]
}`

func TestDeployContractPrepareOkNoEstimate(t *testing.T) {

	ctx, c, _, done := newTestConnector(t)
	defer done()

	var req ffcapi.ContractDeployPrepareRequest
	err := json.Unmarshal([]byte(samplePrepareDeployTX), &req)
	assert.NoError(t, err)
	res, reason, err := c.DeployContractPrepare(ctx, &req)

	assert.NoError(t, err)
	assert.Empty(t, reason)

	assert.Equal(t, int64(1000000), res.Gas.Int64())

}

func TestDeployContractPrepareWithEstimateRevert(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_estimateGas", mock.Anything).Return(fmt.Errorf("pop"))
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").Run(
		func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x08c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000114d75707065747279206465746563746564000000000000000000000000000000")
		},
	).Return(nil)

	var req ffcapi.ContractDeployPrepareRequest
	err := json.Unmarshal([]byte(samplePrepareDeployTX), &req)
	assert.NoError(t, err)
	req.Gas = nil
	res, reason, err := c.DeployContractPrepare(ctx, &req)
	assert.Regexp(t, "FF23021", err)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	assert.Nil(t, res)

}
