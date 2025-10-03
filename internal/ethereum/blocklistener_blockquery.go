// Copyright © 2025 Kaleido, Inc.
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
	"strconv"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

// blockInfoJSONRPC are the info fields we parse from the JSON/RPC response, and cache
type blockInfoJSONRPC struct {
	Number       *ethtypes.HexInteger        `json:"number"`
	Hash         ethtypes.HexBytes0xPrefix   `json:"hash"`
	ParentHash   ethtypes.HexBytes0xPrefix   `json:"parentHash"`
	Timestamp    *ethtypes.HexInteger        `json:"timestamp"`
	Transactions []ethtypes.HexBytes0xPrefix `json:"transactions"`
}

func transformBlockInfo(bi *blockInfoJSONRPC, t *ffcapi.BlockInfo) {
	t.BlockNumber = (*fftypes.FFBigInt)(bi.Number)
	t.BlockHash = bi.Hash.String()
	t.ParentHash = bi.ParentHash.String()
	stringHashes := make([]string, len(bi.Transactions))
	for i, th := range bi.Transactions {
		stringHashes[i] = th.String()
	}
	t.TransactionHashes = stringHashes
}

func (bl *blockListener) addToBlockCache(blockInfo *blockInfoJSONRPC) {
	bl.blockCache.Add(blockInfo.Hash.String(), blockInfo)
	bl.blockCache.Add(blockInfo.Number.BigInt().String(), blockInfo)
}

func (bl *blockListener) getBlockInfoContainsTxHash(ctx context.Context, txHash string) (*ffcapi.MinimalBlockInfo, error) {

	// Query the chain to find the transaction block
	res, reason, receiptErr := bl.c.TransactionReceipt(ctx, &ffcapi.TransactionReceiptRequest{
		TransactionHash: txHash,
	})
	if receiptErr != nil && reason != ffcapi.ErrorReasonNotFound {
		return nil, i18n.WrapError(ctx, receiptErr, msgs.MsgFailedToQueryReceipt, txHash)
	}
	if res == nil {
		return nil, nil
	}
	txBlockHash := res.BlockHash
	txBlockNumber := res.BlockNumber.Uint64()
	// get the parent hash of the transaction block
	bi, reason, err := bl.getBlockInfoByNumber(ctx, txBlockNumber, true, "", txBlockHash)
	if err != nil && reason != ffcapi.ErrorReasonNotFound { // if the block info is not found, then there could be a fork, twe don't throw error in this case and treating it as block not found
		return nil, i18n.WrapError(ctx, err, msgs.MsgFailedToQueryBlockInfo, txHash)
	}
	if bi == nil {
		return nil, nil
	}

	return &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(bi.Number.BigInt().Uint64()),
		BlockHash:   bi.Hash.String(),
		ParentHash:  bi.ParentHash.String(),
	}, nil
}

func (bl *blockListener) getBlockInfoByNumber(ctx context.Context, blockNumber uint64, allowCache bool, expectedParentHashStr string, expectedBlockHashStr string) (*blockInfoJSONRPC, ffcapi.ErrorReason, error) {
	var blockInfo *blockInfoJSONRPC
	if allowCache {
		cached, ok := bl.blockCache.Get(strconv.FormatUint(blockNumber, 10))
		if ok {
			blockInfo = cached.(*blockInfoJSONRPC)
			if (expectedParentHashStr != "" && blockInfo.ParentHash.String() != expectedParentHashStr) || (expectedBlockHashStr != "" && blockInfo.Hash.String() != expectedBlockHashStr) {
				log.L(ctx).Debugf("Block cache miss for block %d due to mismatched parent hash expected=%s found=%s", blockNumber, expectedParentHashStr, blockInfo.ParentHash)
				blockInfo = nil
			}
		}
	}

	if blockInfo == nil {
		rpcErr := bl.backend.CallRPC(ctx, &blockInfo, "eth_getBlockByNumber", ethtypes.NewHexIntegerU64(blockNumber), false /* only the txn hashes */)
		if rpcErr != nil {
			return nil, ffcapi.ErrorReason(""), rpcErr.Error()
		}
		if blockInfo == nil {
			return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
		}
		bl.addToBlockCache(blockInfo)
	}

	return blockInfo, "", nil
}

func (bl *blockListener) getBlockInfoByHash(ctx context.Context, hash0xString string) (*blockInfoJSONRPC, error) {
	var blockInfo *blockInfoJSONRPC
	cached, ok := bl.blockCache.Get(hash0xString)
	if ok {
		blockInfo = cached.(*blockInfoJSONRPC)
	}

	if blockInfo == nil {
		rpcErr := bl.backend.CallRPC(ctx, &blockInfo, "eth_getBlockByHash", hash0xString, false /* only the txn hashes */)
		if rpcErr != nil || blockInfo == nil {
			var err error
			if rpcErr != nil {
				err = rpcErr.Error()
			}
			return nil, err
		}
		bl.addToBlockCache(blockInfo)
	}

	return blockInfo, nil
}
