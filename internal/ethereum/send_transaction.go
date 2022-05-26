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

	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

func (c *ethConnector) sendTransaction(ctx context.Context, payload []byte) (interface{}, ffcapi.ErrorReason, error) {

	var req ffcapi.SendTransactionRequest
	err := json.Unmarshal(payload, &req)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

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
	return &ffcapi.SendTransactionResponse{
		TransactionHash: txHash.String(),
	}, "", nil

}
