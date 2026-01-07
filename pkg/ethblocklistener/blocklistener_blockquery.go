// Copyright © 2026 Kaleido, Inc.
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

package ethblocklistener

import (
	"context"
	"strconv"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-evmconnect/pkg/ethrpc"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

func (bl *blockListener) addToBlockCache(blockInfo *ethrpc.BlockInfoJSONRPC) {
	bl.blockCache.Add(blockInfo.Hash.String(), blockInfo)
	bl.blockCache.Add(blockInfo.Number.BigInt().String(), blockInfo)
}

func (bl *blockListener) getBlockInfoContainsTxHash(ctx context.Context, txHash string) (*ffcapi.MinimalBlockInfo, *ethrpc.TxReceiptJSONRPC, error) {

	// Query the chain to find the transaction block
	receipt, receiptErr := bl.getTransactionReceipt(ctx, txHash)
	if receiptErr != nil {
		return nil, nil, i18n.WrapError(ctx, receiptErr.Error(), msgs.MsgFailedToQueryReceipt, txHash)
	}
	if receipt == nil {
		return nil, nil, nil
	}
	txBlockHash := receipt.BlockHash
	txBlockNumber := receipt.BlockNumber.Uint64()
	// get the parent hash of the transaction block
	bi, err := bl.GetBlockInfoByNumber(ctx, txBlockNumber, true, "", txBlockHash.String())
	if err != nil {
		return nil, nil, i18n.WrapError(ctx, err, msgs.MsgFailedToQueryBlockInfo, txHash)
	}
	if bi == nil {
		// if the block info is not found, then there could be a fork, twe don't throw error in this case and treating it as block not found
		return nil, nil, nil
	}

	return &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(bi.Number.BigInt().Uint64()),
		BlockHash:   bi.Hash.String(),
		ParentHash:  bi.ParentHash.String(),
	}, receipt, nil
}

func (bl *blockListener) getTransactionReceipt(ctx context.Context, txHash string) (ethReceipt *ethrpc.TxReceiptJSONRPC, rpcErr *rpcbackend.RPCError) {
	// Get the receipt in the back-end JSON/RPC format
	rpcErr = bl.backend.CallRPC(ctx, &ethReceipt, "eth_getTransactionReceipt", txHash)
	return
}

func (bl *blockListener) GetBlockInfoByNumber(ctx context.Context, blockNumber uint64, allowCache bool, expectedParentHashStr string, expectedBlockHashStr string) (*ethrpc.BlockInfoJSONRPC, error) {
	var blockInfo *ethrpc.BlockInfoJSONRPC
	if allowCache {
		cached, ok := bl.blockCache.Get(strconv.FormatUint(blockNumber, 10))
		if ok {
			blockInfo = cached.(*ethrpc.BlockInfoJSONRPC)
			if (expectedParentHashStr != "" && blockInfo.ParentHash.String() != expectedParentHashStr) || (expectedBlockHashStr != "" && blockInfo.Hash.String() != expectedBlockHashStr) {
				log.L(ctx).Debugf("Block cache miss for block %d due to mismatched parent hash expected=%s found=%s", blockNumber, expectedParentHashStr, blockInfo.ParentHash)
				blockInfo = nil
			}
		}
	}

	if blockInfo == nil {
		rpcErr := bl.backend.CallRPC(ctx, &blockInfo, "eth_getBlockByNumber", ethtypes.NewHexIntegerU64(blockNumber), false /* only the txn hashes */)
		if rpcErr != nil {
			return nil, rpcErr.Error()
		}
		if blockInfo == nil {
			return nil, nil
		}
		if !bl.IncludeLogsBloom {
			blockInfo.LogsBloom = nil
		}
		bl.addToBlockCache(blockInfo)
	}

	return blockInfo, nil
}

func (bl *blockListener) GetBlockInfoByHash(ctx context.Context, hash0xString string) (*ethrpc.BlockInfoJSONRPC, error) {
	var blockInfo *ethrpc.BlockInfoJSONRPC
	cached, ok := bl.blockCache.Get(hash0xString)
	if ok {
		blockInfo = cached.(*ethrpc.BlockInfoJSONRPC)
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
		if !bl.IncludeLogsBloom {
			blockInfo.LogsBloom = nil
		}
		bl.addToBlockCache(blockInfo)
	}

	return blockInfo, nil
}
