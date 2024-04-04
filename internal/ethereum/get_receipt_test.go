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
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const sampleGetReceipt = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "get_receipt"
	},
	"transactionHash": "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2"
}`

const sampleJSONRPCReceipt = `{
	"blockHash": "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6",
	"blockNumber": "0x7b9",
	"contractAddress": "0x87ae94ab290932c4e6269648bb47c86978af4436",
	"cumulativeGasUsed": "0x8414",
	"effectiveGasPrice": "0x0",
	"from": "0x2b1c769ef5ad304a4889f2a07a6617cd935849ae",
	"gasUsed": "0x8414",
	"logs": [
	{
		"address": "0x302259069aaa5b10dc6f29a9a3f72a8e52837cc3",
		"topics": [
		"0x805721bc246bccc732581be0c0aa2dd8f7ec93e97ba4b307be84428c98b0a12f"
		],
		"data": "0x0000000000000000000000002b1c769ef5ad304a4889f2a07a6617cd935849ae00000000000000000000000000000000000000000000000000000000625829cc00000000000000000000000000000000000000000000000000000000000000e01f64cabbf2b44bff810396f2cb08186c2d460c2bd1c44058bc058267d554e724973b16c67dbcade6c509329de6aad8037bb024b7a996129f731b9f68ac5fcd9f00000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000000966665f73797374656d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e516d546a587065445154326a377063583145347445764379334665554a71744374737036464c5762535553724a4e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014a1ad4027f59715bca7fd30dc0121be0542c713f7a2470c415e8b1d9e7df372c",
		"blockNumber": "0x5",
		"transactionHash": "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2",
		"transactionIndex": "0x0",
		"blockHash": "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6",
		"logIndex": "0x0",
		"removed": false
	}
	],
	"logsBloom": "0x00000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000100000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000",
	"status": "0x1",
	"to": "0x302259069aaa5b10dc6f29a9a3f72a8e52837cc3",
	"transactionHash": "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2",
	"transactionIndex": "0x1e",
	"type": "0x0"
}`

const sampleJSONRPCReceiptFailed = `{
	"blockHash": "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6",
	"blockNumber": "0x7b9",
	"contractAddress": "0x87ae94ab290932c4e6269648bb47c86978af4436",
	"cumulativeGasUsed": "0x8414",
	"effectiveGasPrice": "0x0",
	"from": "0x2b1c769ef5ad304a4889f2a07a6617cd935849ae",
	"gasUsed": "0x8414",
	"logs": [],
	"logsBloom": "0x00000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000100000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000",
	"status": "0",
	"to": "0x302259069aaa5b10dc6f29a9a3f72a8e52837cc3",
	"transactionHash": "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2",
	"transactionIndex": "0x1e",
	"type": "0x0"
}`

const sampleTransactionTraceGeth = `{
	"gas": 23512,
	"failed": true,
	"returnValue": "08c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000114e6f7420656e6f75676820746f6b656e73000000000000000000000000000000",
	"structLogs": []
}
`

const sampleTransactionTraceNoReturnValue = `{
	"gas": 23512,
	"failed": true,
	"structLogs": []
}
`

const sampleTransactionTraceGethInvalidHex = `{
	"gas": 23512,
	"failed": true,
	"returnValue": "invalid hex",
	"structLogs": []
}
`

const sampleTransactionTraceGethInvalidCallData = `{
	"gas": 23512,
	"failed": true,
	"returnValue": "0badca11da7a",
	"structLogs": []
}
`

const sampleTransactionTraceBesu = `{
	"gas": 23512,
	"failed": true,
	"returnValue": "",
	"structLogs": [
		{
			"pc": 0,
			"op": "PUSH1",
			"gas": 78404,
			"gasCost": 3,
			"depth": 1,
			"stack": [],
			"memory": [],
			"storage": {},
			"reason": null
		},
		{
			"pc": 4,
			"op": "MSTORE",
			"gas": 78398,
			"gasCost": 12,
			"depth": 1,
			"stack": [
				"0000000000000000000000000000000000000000000000000000000000000080",
				"0000000000000000000000000000000000000000000000000000000000000040"
			],
			"memory": [
				"0000000000000000000000000000000000000000000000000000000000000000",
				"0000000000000000000000000000000000000000000000000000000000000000",
				"0000000000000000000000000000000000000000000000000000000000000080"
			],
			"storage": {},
			"reason": null
		},
		{
			"pc": 829,
			"op": "REVERT",
			"gas": 76488,
			"gasCost": 0,
			"depth": 1,
			"stack": [
				"00000000000000000000000000000000000000000000000000000000a9059cbb",
				"0000000000000000000000000000000000000000000000000000000000000129",
				"000000000000000000000000b5855faa164db05e70fd3476e3540fc8c4053a01",
				"00000000000000000000000000000000000000000000000000000000000f4241",
				"0000000000000000000000000000000000000000000000000000000000000064",
				"0000000000000000000000000000000000000000000000000000000000000080"
			],
			"memory": [
				"00000000000000000000000046ec33d9fd840ae95f36c3449cf46041ff6fb886",
				"0000000000000000000000000000000000000000000000000000000000000004",
				"0000000000000000000000000000000000000000000000000000000000000080",
				"0000000000000000000000000000000000000000000000000000000000000000",
				"08c379a000000000000000000000000000000000000000000000000000000000",
				"0000002000000000000000000000000000000000000000000000000000000000",
				"000000114e6f7420656e6f75676820746f6b656e730000000000000000000000",
				"0000000000000000000000000000000000000000000000000000000000000000"
			],
			"storage": {},
			"reason": "8c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000114e6f7420656e6f75676820746f6b656e73000000000000000000000000000000"
		}
	]
}`

func TestGetReceiptOkSuccess(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceipt), args[1])
			assert.NoError(t, err)
		})

	var req ffcapi.TransactionReceiptRequest
	err := json.Unmarshal([]byte(sampleGetReceipt), &req)
	assert.NoError(t, err)
	res, reason, err := c.TransactionReceipt(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)

	assert.True(t, res.Success)
	assert.Equal(t, int64(1977), res.BlockNumber.Int64())
	assert.Equal(t, int64(30), res.TransactionIndex.Int64())

}

func TestGetReceiptNotFound(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt", mock.Anything).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte("null"), args[1])
			assert.NoError(t, err)
		})

	var req ffcapi.TransactionReceiptRequest
	err := json.Unmarshal([]byte(sampleGetReceipt), &req)
	assert.NoError(t, err)
	res, reason, err := c.TransactionReceipt(ctx, &req)
	assert.Regexp(t, "FF23012", err)
	assert.Equal(t, ffcapi.ErrorReasonNotFound, reason)
	assert.Nil(t, res)

}

func TestGetReceiptError(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt", mock.Anything).
		Return(&rpcbackend.RPCError{Message: "pop"})

	var req ffcapi.TransactionReceiptRequest
	err := json.Unmarshal([]byte(sampleGetReceipt), &req)
	assert.NoError(t, err)
	res, reason, err := c.TransactionReceipt(ctx, &req)
	assert.Regexp(t, "pop", err)
	assert.Empty(t, "", reason)
	assert.Nil(t, res)

}

func TestGetReceiptErrorReasonGeth(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceiptFailed), args[1])
			assert.NoError(t, err)
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "debug_traceTransaction",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleTransactionTraceGeth), args[1])
			assert.NoError(t, err)
		})
	var req ffcapi.TransactionReceiptRequest
	err := json.Unmarshal([]byte(sampleGetReceipt), &req)
	assert.NoError(t, err)
	res, reason, err := c.TransactionReceipt(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)

	assert.False(t, res.Success)
	assert.Contains(t, res.ExtraInfo.String(), "Not enough tokens")

}

func TestGetReceiptErrorReasonBesu(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceiptFailed), args[1])
			assert.NoError(t, err)
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "debug_traceTransaction",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleTransactionTraceBesu), args[1])
			assert.NoError(t, err)
		})
	var req ffcapi.TransactionReceiptRequest
	err := json.Unmarshal([]byte(sampleGetReceipt), &req)
	assert.NoError(t, err)
	res, reason, err := c.TransactionReceipt(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)

	assert.False(t, res.Success)
	assert.Contains(t, res.ExtraInfo.String(), "Not enough tokens")

}

func TestGetReceiptErrorReasonNotFound(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceiptFailed), args[1])
			assert.NoError(t, err)
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "debug_traceTransaction",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleTransactionTraceNoReturnValue), args[1])
			assert.NoError(t, err)
		})
	var req ffcapi.TransactionReceiptRequest
	err := json.Unmarshal([]byte(sampleGetReceipt), &req)
	assert.NoError(t, err)
	res, reason, err := c.TransactionReceipt(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)

	assert.False(t, res.Success)

}

func TestGetReceiptErrorReasonErrorFromHexDecode(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceiptFailed), args[1])
			assert.NoError(t, err)
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "debug_traceTransaction",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleTransactionTraceGethInvalidHex), args[1])
			assert.NoError(t, err)
		})
	var req ffcapi.TransactionReceiptRequest
	err := json.Unmarshal([]byte(sampleGetReceipt), &req)
	assert.NoError(t, err)
	res, reason, err := c.TransactionReceipt(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)

	assert.False(t, res.Success)

}

func TestGetReceiptErrorReasonErrorFromTrace(t *testing.T) {
	// if we get an error tracing the transaction, we ignore it.  Not all nodes support the debug_traceTransaction RPC call

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceiptFailed), args[1])
			assert.NoError(t, err)
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "debug_traceTransaction",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(&rpcbackend.RPCError{Message: "unsupported"}).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleTransactionTraceGeth), args[1])
			assert.NoError(t, err)
		})
	var req ffcapi.TransactionReceiptRequest
	err := json.Unmarshal([]byte(sampleGetReceipt), &req)
	assert.NoError(t, err)
	res, reason, err := c.TransactionReceipt(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)

	assert.False(t, res.Success)

}

func TestGetReceiptErrorReasonErrorFromDecodeCallData(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceiptFailed), args[1])
			assert.NoError(t, err)
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "debug_traceTransaction",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x7d48ae971faf089878b57e3c28e3035540d34f38af395958d2c73c36c57c83a2", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleTransactionTraceGethInvalidCallData), args[1])
			assert.NoError(t, err)
		})
	var req ffcapi.TransactionReceiptRequest
	err := json.Unmarshal([]byte(sampleGetReceipt), &req)
	assert.NoError(t, err)
	res, reason, err := c.TransactionReceipt(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)

	assert.False(t, res.Success)

}

func TestProtocolIDForReceipt(t *testing.T) {
	assert.Equal(t, "000000012345/000042", ProtocolIDForReceipt(fftypes.NewFFBigInt(12345), fftypes.NewFFBigInt(42)))
	assert.Equal(t, "", ProtocolIDForReceipt(nil, nil))
}
