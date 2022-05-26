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
	"fmt"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const sampleSendTX = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "send_transaction"
	},
	"from": "0xb480F96c0a3d6E9e9a263e4665a39bFa6c4d01E8",
	"to": "0xe1a078b9e2b145d0a7387f09277c6ae1d9470771",
	"gas": 1000000,
	"nonce": "111",
	"value": "12345678901234567890123456789",
	"transactionData": "0x60fe47b100000000000000000000000000000000000000000000000000000000feedbeef"
}`

const sampleSendTXBadFrom = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "send_transaction"
	}
}`

const sampleSendTXBadTo = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "send_transaction"
	},
	"from": "0x3088C3B2361e5b12c5270fA0692d2Fa6b29bdB63",
	"to": "bad to"
}`

const sampleSendTXBadData = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "send_transaction"
	},
	"transactionData": "not hex"
}`

const sampleSendTXBadGasPrice = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "send_transaction"
	},
	"from": "0x3088C3B2361e5b12c5270fA0692d2Fa6b29bdB63",
	"gasPrice": "not a number"
}`

const sampleSendTXGasPriceEIP1559 = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "send_transaction"
	},
	"from": "0x3088C3B2361e5b12c5270fA0692d2Fa6b29bdB63",
	"gasPrice": {
		"maxPriorityFeePerGas": 12345,
		"maxFeePerGas": "0xffff"
	}
}`

const sampleSendTXGasPriceLegacy = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "send_transaction"
	},
	"from": "0x3088C3B2361e5b12c5270fA0692d2Fa6b29bdB63",
	"gasPrice": {
		"gasPrice": "0xffff"
	}
}`

func TestSendTransactionOK(t *testing.T) {

	c, mRPC := newTestConnector(t)
	ctx := context.Background()

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_sendTransaction",
		mock.MatchedBy(func(tx *ethsigner.Transaction) bool {
			assert.Equal(t, "0x60fe47b100000000000000000000000000000000000000000000000000000000feedbeef", tx.Data.String())
			return true
		})).
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x123456")
		}).
		Return(nil)

	iRes, reason, err := c.sendTransaction(ctx, []byte(sampleSendTX))
	assert.NoError(t, err)
	assert.Empty(t, reason)

	res := iRes.(*ffcapi.SendTransactionResponse)
	assert.Equal(t, "0x123456", res.TransactionHash)

	mRPC.AssertExpectations(t)

}

func TestSendTransactionFail(t *testing.T) {

	c, mRPC := newTestConnector(t)
	ctx := context.Background()

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_sendTransaction",
		mock.MatchedBy(func(tx *ethsigner.Transaction) bool {
			assert.Equal(t, "0x60fe47b100000000000000000000000000000000000000000000000000000000feedbeef", tx.Data.String())
			return true
		})).
		Return(fmt.Errorf("pop"))

	iRes, reason, err := c.sendTransaction(ctx, []byte(sampleSendTX))
	assert.Regexp(t, "pop", err)
	assert.Empty(t, reason)
	assert.Nil(t, iRes)

	mRPC.AssertExpectations(t)

}

func TestSendErrorMapping(t *testing.T) {

	assert.Equal(t, ffcapi.ErrorReasonNonceTooLow, mapError(sendRPCMethods, fmt.Errorf("nonce too low")))
	assert.Equal(t, ffcapi.ErrorReasonInsufficientFunds, mapError(sendRPCMethods, fmt.Errorf("insufficient funds")))
	assert.Equal(t, ffcapi.ErrorReasonTransactionUnderpriced, mapError(sendRPCMethods, fmt.Errorf("transaction underpriced")))
	assert.Equal(t, ffcapi.ErrorKnownTransaction, mapError(sendRPCMethods, fmt.Errorf("known transaction")))

}

func TestSendTransactionBadFrom(t *testing.T) {

	c, _ := newTestConnector(t)
	ctx := context.Background()

	iRes, reason, err := c.sendTransaction(ctx, []byte(sampleSendTXBadFrom))
	assert.Regexp(t, "FF23019", err)
	assert.Equal(t, ffcapi.ErrorReasonInvalidInputs, reason)
	assert.Nil(t, iRes)

}

func TestSendTransactionBadTo(t *testing.T) {

	c, _ := newTestConnector(t)
	ctx := context.Background()

	iRes, reason, err := c.sendTransaction(ctx, []byte(sampleSendTXBadTo))
	assert.Regexp(t, "FF23020", err)
	assert.Equal(t, ffcapi.ErrorReasonInvalidInputs, reason)
	assert.Nil(t, iRes)

}

func TestSendTransactionBadData(t *testing.T) {

	c, _ := newTestConnector(t)
	ctx := context.Background()

	iRes, reason, err := c.sendTransaction(ctx, []byte(sampleSendTXBadData))
	assert.Regexp(t, "FF23018", err)
	assert.Equal(t, ffcapi.ErrorReasonInvalidInputs, reason)
	assert.Nil(t, iRes)

}

func TestSendTransactionBadGasPrice(t *testing.T) {

	c, _ := newTestConnector(t)
	ctx := context.Background()

	iRes, reason, err := c.sendTransaction(ctx, []byte(sampleSendTXBadGasPrice))
	assert.Regexp(t, "FF23015", err)
	assert.Equal(t, ffcapi.ErrorReasonInvalidInputs, reason)
	assert.Nil(t, iRes)

}

func TestSendTransactionGasPriceEIP1559(t *testing.T) {

	c, mRPC := newTestConnector(t)
	ctx := context.Background()

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_sendTransaction",
		mock.MatchedBy(func(tx *ethsigner.Transaction) bool {
			assert.Equal(t, int64(65535), tx.MaxFeePerGas.BigInt().Int64())
			assert.Equal(t, int64(12345), tx.MaxPriorityFeePerGas.BigInt().Int64())
			return true
		})).
		Return(nil)

	iRes, reason, err := c.sendTransaction(ctx, []byte(sampleSendTXGasPriceEIP1559))
	assert.NoError(t, err)
	assert.Empty(t, reason)
	assert.NotNil(t, iRes)

}

func TestSendTransactionGasPriceLegacyNested(t *testing.T) {

	c, mRPC := newTestConnector(t)
	ctx := context.Background()

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_sendTransaction",
		mock.MatchedBy(func(tx *ethsigner.Transaction) bool {
			assert.Equal(t, int64(65535), tx.GasPrice.BigInt().Int64())
			return true
		})).
		Return(nil)

	iRes, reason, err := c.sendTransaction(ctx, []byte(sampleSendTXGasPriceLegacy))
	assert.NoError(t, err)
	assert.Empty(t, reason)
	assert.NotNil(t, iRes)

}

func TestSendTransactionBadPayload(t *testing.T) {

	c, _ := newTestConnector(t)
	ctx := context.Background()

	iRes, reason, err := c.sendTransaction(ctx, []byte("!not json!"))
	assert.Regexp(t, "invalid", err)
	assert.Equal(t, ffcapi.ErrorReasonInvalidInputs, reason)
	assert.Nil(t, iRes)

}
