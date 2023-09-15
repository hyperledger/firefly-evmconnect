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

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const sampleExecQuery = `{
  "ffcapi": {
    "version": "v1.0.0",
    "id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
    "type": "exec_query"
  },
  "from": "0xb480F96c0a3d6E9e9a263e4665a39bFa6c4d01E8",
  "to": "0xe1a078b9e2b145d0a7387f09277c6ae1d9470771",
  "nonce": "222",
  "method": {
    "inputs": [
      {
        "internalType":" uint256",
        "name": "x",
        "type": "uint256"
      }
    ],
    "name":"set",
    "outputs":[
      {
        "internalType":"uint256",
        "name": "",
        "type": "uint256"
      },
      {
        "type": "string"
      }
    ],
    "stateMutability":"nonpayable",
    "type":"function"
  },
  "errors": [
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "x",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "y",
          "type": "uint256"
        }
      ],
      "name": "GreaterThanTen",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "x",
          "type": "string"
        }
      ],
      "name": "LessThanOne",
      "type": "error"
    }
  ],
  "params": [ 4276993775 ]
}`

func TestExecQueryOKResponse(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call",
		mock.MatchedBy(func(tx *ethsigner.Transaction) bool {
			assert.Equal(t, "0x60fe47b100000000000000000000000000000000000000000000000000000000feedbeef", tx.Data.String())
			return true
		}),
		"latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x00000000000000000000000000000000000000000000000000000000baadf00d0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000b68656c6c6f20776f726c64000000000000000000000000000000000000000000")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)

	res, reason, err := c.QueryInvoke(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)
	assert.JSONEq(t, `{"output": "3131961357", "output1":"hello world"}`, res.Outputs.String())

}

func TestExecQueryOKNilResponse(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call",
		mock.MatchedBy(func(tx *ethsigner.Transaction) bool {
			assert.Equal(t, "0x60fe47b100000000000000000000000000000000000000000000000000000000feedbeef", tx.Data.String())
			return true
		}),
		"latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	res, reason, err := c.QueryInvoke(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)
	assert.JSONEq(t, "null", res.Outputs.String())

}

func TestExecQueryCustomErrorRevertData(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x391ad4e000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000014")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	expectedError := i18n.NewError(ctx, msgs.MsgReverted, `GreaterThanTen("20", "20")`)
	assert.Equal(t, expectedError.Error(), err.Error())

}

func TestExecQueryCustomErrorRevertDataExceedsBalance(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002645524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e63650000000000000000000000000000000000000000000000000000")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	expectedError := i18n.NewError(ctx, msgs.MsgReverted, `ERC20: transfer amount exceeds balance`)
	assert.Equal(t, expectedError.Error(), err.Error())

}

func TestExecQueryCustomErrorRevertDataNotEnoughEther(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001a4e6f7420656e6f7567682045746865722070726f76696465642e000000000000")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	expectedError := i18n.NewError(ctx, msgs.MsgReverted, `Not enough Ether provided.`)
	assert.Equal(t, expectedError.Error(), err.Error())

}

func TestExecQueryCustomErrorRevertDataTransferFromZeroAddress(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002545524332303a207472616e736665722066726f6d20746865207a65726f2061646472657373000000000000000000000000000000000000000000000000000000")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	expectedError := i18n.NewError(ctx, msgs.MsgReverted, `ERC20: transfer from the zero address`)
	assert.Equal(t, expectedError.Error(), err.Error())

}

func TestExecQueryCustomErrorRevertDataBadOutput(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x053b20290000000000000000000000000000000000000000000000000000000000000020")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	expectedError := i18n.NewError(ctx, msgs.MsgReverted, `0x053b20290000000000000000000000000000000000000000000000000000000000000020`)
	assert.Equal(t, expectedError.Error(), err.Error())

}

func TestExecQueryCustomErrorBadRevertData(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Return(&rpcbackend.RPCError{Message: "pop", Data: "bad data"}).
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x053b20290000000000000000000000000000000000000000000000000000000000000020")
		})

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, _, err = c.QueryInvoke(ctx, &req)
	assert.Error(t, err)
	assert.Regexp(t, "pop", err)

}

func TestExecQueryBadErrorsABI(t *testing.T) {

	ctx, c, _, done := newTestConnector(t)
	defer done()

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	req.Errors = []*fftypes.JSONAny{fftypes.JSONAnyPtr(`[`)}
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonInvalidInputs, reason)

}

func TestExecQueryBadRevertData(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x08c379a000000000000000000000000000000000000000000000000000000000baadf00d")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	assert.Regexp(t, "FF23021.*0x08c379a000000000000000000000000000000000000000000000000000000000baadf00d", err)

}

func TestExecQueryBadReturnData(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x00000000000000000000000000000000000000000000000000000000baadf00d")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(`{
			"ffcapi": {
				"version": "v1.0.0",
				"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
				"type": "exec_query"
			},
			"from": "0xb480F96c0a3d6E9e9a263e4665a39bFa6c4d01E8",
			"to": "0xe1a078b9e2b145d0a7387f09277c6ae1d9470771",
			"nonce": "222",
			"method": {
				"inputs": [],
				"name":"set",
				"outputs":[{"type":"uint256[10]"}],
				"stateMutability":"nonpayable",
				"type":"function"
			},
			"params": [ ]
		}`), &req)
	assert.NoError(t, err)

	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Empty(t, reason)
	assert.Regexp(t, "FF23023", err)

}

func TestExecQueryFailCall(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").Return(&rpcbackend.RPCError{Message: "pop"})

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, _, err = c.QueryInvoke(ctx, &req)
	assert.Regexp(t, "pop", err)

}

func TestExecQueryFailBadToAddress(t *testing.T) {

	ctx, c, _, done := newTestConnector(t)
	defer done()

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(`{
		"ffcapi": {
			"version": "v1.0.0",
			"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
			"type": "exec_query"
		},
		"from": "0xb480F96c0a3d6E9e9a263e4665a39bFa6c4d01E8",
		"to": "wrong",
		"nonce": "222",
		"method": {
			"inputs": [],
			"name":"set",
			"outputs":[],
			"stateMutability":"nonpayable",
			"type":"function"
		},
		"params": [ ]
	}`), &req)
	assert.NoError(t, err)
	_, _, err = c.QueryInvoke(ctx, &req)
	assert.Regexp(t, "FF23020", err)

}

func TestExecQueryFailBadToParams(t *testing.T) {

	ctx, c, _, done := newTestConnector(t)
	defer done()

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(`{
		"ffcapi": {
			"version": "v1.0.0",
			"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
			"type": "exec_query"
		},
		"from": "0xb480F96c0a3d6E9e9a263e4665a39bFa6c4d01E8",
		"to": "wrong",
		"nonce": "222",
		"method": {
			"inputs": [],
			"name":"set",
			"outputs":[],
			"stateMutability":"nonpayable",
			"type":"function"
		},
		"params": [ "unexpected extra param" ]
	}`), &req)
	assert.NoError(t, err)
	_, _, err = c.QueryInvoke(ctx, &req)
	assert.Regexp(t, "FF22037", err)

}
