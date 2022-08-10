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

	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

func (c *ethConnector) estimateGas(ctx context.Context, tx *ethsigner.Transaction, method *abi.Entry) (*ethtypes.HexInteger, ffcapi.ErrorReason, error) {

	// Do the gas estimation
	var gasEstimate ethtypes.HexInteger
	err := c.backend.Invoke(ctx, &gasEstimate, "eth_estimateGas", tx)
	if err != nil {
		// If it fails, fall back to an eth_call to see if we get a reverted reason
		_, reason, errCall := c.callTransaction(ctx, tx, method)
		if reason == ffcapi.ErrorReasonTransactionReverted {
			return nil, reason, errCall
		}
		log.L(ctx).Errorf("Gas estimation failed for a non-revert reason: %s (call result: %v)", err, errCall)
		// Return the original error - as the eth_call did not give us a revert result (it might even
		// have succeeded). So we need to fall back to the original error.
		return nil, mapError(callRPCMethods, err), err
	}

	// Multiply the gas estimate by the configured factor
	fGasEstimate := new(big.Float).SetInt(gasEstimate.BigInt())
	_ = fGasEstimate.Mul(fGasEstimate, c.gasEstimationFactor)
	_, _ = fGasEstimate.Int(gasEstimate.BigInt())
	return &gasEstimate, "", nil
}
