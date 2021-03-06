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
	"encoding/json"
	"fmt"

	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

func (c *ethConnector) prepareTransaction(ctx context.Context, payload []byte) (interface{}, ffcapi.ErrorReason, error) {

	var req ffcapi.PrepareTransactionRequest
	err := json.Unmarshal(payload, &req)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	// Parse the input JSON data, to build the call data
	callData, method, err := c.prepareCallData(ctx, &req.TransactionInput)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	// Build the base transaction object
	tx, err := c.buildTx(ctx, req.From, req.To, req.Nonce, req.Gas, req.Value, callData)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	if req.Gas == nil || req.Gas.Int().Sign() == 0 {
		// If a value for gas has not been supplied, do a gas estimate
		gas, reason, err := c.estimateGas(ctx, tx, method)
		if err != nil {
			return nil, reason, err
		}
		req.Gas = (*fftypes.FFBigInt)(gas)
	}
	log.L(ctx).Infof("Prepared transaction method=%s dataLen=%d gas=%s", method.String(), len(callData), req.Gas.Int())

	return &ffcapi.PrepareTransactionResponse{
		Gas:             req.Gas,
		TransactionData: ethtypes.HexBytes0xPrefix(callData).String(),
	}, "", nil

}

func (c *ethConnector) prepareCallData(ctx context.Context, req *ffcapi.TransactionInput) ([]byte, *abi.Entry, error) {

	// Parse the method ABI
	var method *abi.Entry
	err := json.Unmarshal([]byte(req.Method), &method)
	if err != nil {
		return nil, nil, i18n.NewError(ctx, msgs.MsgUnmarshalABIFail, err)
	}

	// Parse the params into the standard semantics of Go JSON unmarshalling, with []interface{}
	ethParams := make([]interface{}, len(req.Params))
	for i, p := range req.Params {
		if p != nil {
			err := json.Unmarshal([]byte(*p), &ethParams[i])
			if err != nil {
				return nil, nil, i18n.NewError(ctx, msgs.MsgUnmarshalParamFail, i, err)
			}
		}
	}

	// Match the parameters to the ABI call data for the method.
	// Note the FireFly ABI decoding package handles formatting errors / translation etc.
	paramValues, err := method.Inputs.ParseExternalDataCtx(ctx, ethParams)
	if err != nil {
		return nil, nil, err
	}
	callData, err := method.EncodeCallDataCtx(ctx, paramValues)
	if err != nil {
		return nil, nil, err
	}

	return callData, method, err

}

func (c *ethConnector) buildTx(ctx context.Context, fromString, toString string, nonce, gas, value *fftypes.FFBigInt, data []byte) (*ethsigner.Transaction, error) {

	// Verify the from address, and normalize formatting to pass downstream
	from, err := ethtypes.NewAddress(fromString)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgInvalidFromAddress, fromString, err)
	}

	// Parse the to address (if set)
	var to *ethtypes.Address0xHex
	if toString != "" {
		to, err = ethtypes.NewAddress(toString)
		if err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgInvalidToAddress, toString, err)
		}
	}

	return &ethsigner.Transaction{
		From:     json.RawMessage(fmt.Sprintf(`"%s"`, from)),
		To:       to,
		Nonce:    (*ethtypes.HexInteger)(nonce),
		GasLimit: (*ethtypes.HexInteger)(gas),
		Value:    (*ethtypes.HexInteger)(value),
		Data:     data,
	}, nil

}

// mapGasPrice handles a variety of inputs from the Transaction Manager policy engine
//   sending the FFCAPI request. Specifically:
//   - {"maxFeePerGas": "12345", "maxPriorityFeePerGas": "2345"} - EIP-1559 gas price
//   - {"gasPrice": "12345"} - legacy gas price
//   - "12345" - same as  {"gasPrice": "12345"}
//   - nil - same as {"gasPrice": "0"}
// Anything else will return an error
func (c *ethConnector) mapGasPrice(ctx context.Context, input *fftypes.JSONAny, tx *ethsigner.Transaction) error {
	if input == nil {
		tx.GasPrice = ethtypes.NewHexInteger64(0)
		return nil
	}
	gasPriceObject := input.JSONObjectNowarn()
	tx.MaxPriorityFeePerGas = (*ethtypes.HexInteger)(gasPriceObject.GetInteger("maxPriorityFeePerGas"))
	tx.MaxFeePerGas = (*ethtypes.HexInteger)(gasPriceObject.GetInteger("maxFeePerGas"))
	if tx.MaxPriorityFeePerGas.BigInt().Sign() > 0 || tx.MaxFeePerGas.BigInt().Sign() > 0 {
		log.L(ctx).Debugf("maxPriorityFeePerGas=%s maxFeePerGas=%s", tx.MaxPriorityFeePerGas, tx.MaxFeePerGas)
		return nil
	}
	tx.GasPrice = (*ethtypes.HexInteger)(gasPriceObject.GetInteger("gasPrice"))
	if tx.GasPrice.BigInt().Sign() == 0 {
		err := json.Unmarshal(input.Bytes(), &tx.GasPrice)
		if err != nil {
			return i18n.NewError(ctx, msgs.MsgGasPriceError, input.String())
		}
	}
	log.L(ctx).Debugf("gasPrice=%s", tx.GasPrice)
	return nil
}
