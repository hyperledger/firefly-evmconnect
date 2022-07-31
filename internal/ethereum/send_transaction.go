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
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

func (c *ethConnector) TransactionSend(ctx context.Context, req *ffcapi.TransactionSendRequest) (*ffcapi.TransactionSendResponse, ffcapi.ErrorReason, error) {

	txData, err := hex.DecodeString(strings.TrimPrefix(req.TransactionData, "0x"))
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, i18n.NewError(ctx, msgs.MsgInvalidTXData, req.TransactionData, err)
	}

	tx, err := c.buildTx(ctx, req.From, req.To, req.Nonce, req.Gas, req.Value, txData)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	err = c.mapGasPrice(ctx, req.GasPrice, tx)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	var txHash ethtypes.HexBytes0xPrefix
	err = c.backend.Invoke(ctx, &txHash, "eth_sendTransaction", tx)
	if err != nil {
		return nil, mapError(sendRPCMethods, err), err
	}
	return &ffcapi.TransactionSendResponse{
		TransactionHash: txHash.String(),
	}, "", nil

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
	maxPriorityFeePerGas := (*ethtypes.HexInteger)(gasPriceObject.GetInteger("maxPriorityFeePerGas"))
	maxFeePerGas := (*ethtypes.HexInteger)(gasPriceObject.GetInteger("maxFeePerGas"))
	if tx.MaxPriorityFeePerGas.BigInt().Sign() > 0 || tx.MaxFeePerGas.BigInt().Sign() > 0 {
		tx.MaxPriorityFeePerGas = maxPriorityFeePerGas
		tx.MaxFeePerGas = maxFeePerGas
		log.L(ctx).Debugf("maxPriorityFeePerGas=%s maxFeePerGas=%s", tx.MaxPriorityFeePerGas, tx.MaxFeePerGas)
		return nil
	}
	tx.GasPrice = (*ethtypes.HexInteger)(gasPriceObject.GetInteger("gasPrice"))
	log.L(ctx).Debugf("maxPriorityFeePerGas=%s maxFeePerGas=%s gasPrice=%s", tx.MaxPriorityFeePerGas, tx.MaxFeePerGas, tx.GasPrice)
	if tx.GasPrice.BigInt().Sign() == 0 {
		err := json.Unmarshal(input.Bytes(), &tx.GasPrice)
		if err != nil {
			return i18n.NewError(ctx, msgs.MsgGasPriceError, input.String())
		}
	}
	log.L(ctx).Debugf("gasPrice=%s", tx.GasPrice)
	return nil
}
