// Copyright © 2023 Kaleido, Inc.
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
	"math/big"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

func (c *ethConnector) estimateGas(ctx context.Context, tx *ethsigner.Transaction, method *abi.Entry, errors []*abi.Entry) (*ethtypes.HexInteger, ffcapi.ErrorReason, error) {

	// Do the gas estimation
	var gasEstimate ethtypes.HexInteger
	rpcErr := c.backend.CallRPC(ctx, &gasEstimate, "eth_estimateGas", tx)
	if rpcErr != nil {
		// some Ethereum implementations (eg. geth 1.10) returns the revert details on the estimateGas calls,
		// so check that before making the eth_call request
		if rpcErr.Data != "" {
			var revertData ethtypes.HexBytes0xPrefix
			e1 := json.Unmarshal(rpcErr.Data.Bytes(), &revertData)
			if e1 != nil {
				return nil, mapError(callRPCMethods, e1), e1
			}
			revertReason, ok := processRevertReason(ctx, revertData, errors)
			if revertReason != "" {
				if ok {
					return nil, ffcapi.ErrorReasonTransactionReverted, i18n.NewError(ctx, msgs.MsgReverted, revertReason)
				}
				return nil, ffcapi.ErrorReasonTransactionReverted, i18n.NewError(ctx, msgs.MsgReverted, revertReason)
			}
		}

		// If it fails, fall back to an eth_call to see if we get a reverted reason
		_, reason, errCall := c.callTransaction(ctx, tx, method, errors)
		if reason == ffcapi.ErrorReasonTransactionReverted {
			return nil, reason, errCall
		}
		log.L(ctx).Errorf("Gas estimation failed for a non-revert reason: %s (call result: %v)", rpcErr.Message, errCall)
		// Return the original error - as the eth_call did not give us a revert result (it might even
		// have succeeded). So we need to fall back to the original error.
		return nil, mapError(callRPCMethods, rpcErr.Error()), rpcErr.Error()
	}

	// Multiply the gas estimate by the configured factor
	fGasEstimate := new(big.Float).SetInt(gasEstimate.BigInt())
	_ = fGasEstimate.Mul(fGasEstimate, c.gasEstimationFactor)
	_, _ = fGasEstimate.Int(gasEstimate.BigInt())
	return &gasEstimate, "", nil
}
