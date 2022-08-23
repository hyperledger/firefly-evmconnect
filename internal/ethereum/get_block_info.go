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

func (c *ethConnector) addToBlockCache(blockInfo *blockInfoJSONRPC) {
	c.blockCache.Add(blockInfo.Hash.String(), blockInfo)
	c.blockCache.Add(blockInfo.Number.BigInt().String(), blockInfo)
}

func (c *ethConnector) getBlockInfoByNumber(ctx context.Context, blockNumber int64, allowCache bool, expectedHashStr string) (*blockInfoJSONRPC, error) {
	var blockInfo *blockInfoJSONRPC
	if allowCache {
		cached, ok := c.blockCache.Get(strconv.FormatInt(blockNumber, 10))
		if ok {
			blockInfo = cached.(*blockInfoJSONRPC)
			if expectedHashStr != "" && blockInfo.ParentHash.String() != expectedHashStr {
				log.L(ctx).Debugf("Block cache miss for block %d due to mismatched parent hash expected=%s found=%s", blockNumber, expectedHashStr, blockInfo.ParentHash)
				blockInfo = nil
			}
		}
	}

	if blockInfo == nil {
		err := c.backend.Invoke(ctx, &blockInfo, "eth_getBlockByNumber", ethtypes.NewHexInteger64(blockNumber), false /* only the txn hashes */)
		if err != nil {
			if mapError(blockRPCMethods, err) == ffcapi.ErrorReasonNotFound {
				log.L(ctx).Debugf("Received error signifying 'block not found': '%s'", err)
				return nil, nil
			}
			return nil, err
		}
		if blockInfo == nil {
			return nil, err
		}
		c.addToBlockCache(blockInfo)
	}

	return blockInfo, nil
}

func (c *ethConnector) BlockInfoByNumber(ctx context.Context, req *ffcapi.BlockInfoByNumberRequest) (*ffcapi.BlockInfoByNumberResponse, ffcapi.ErrorReason, error) {

	blockInfo, err := c.getBlockInfoByNumber(ctx, req.BlockNumber.Int64(), true, req.ExpectedParentHash)
	if err != nil {
		return nil, ffcapi.ErrorReason(""), err
	}
	if blockInfo == nil {
		return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
	}

	res := &ffcapi.BlockInfoByNumberResponse{}
	transformBlockInfo(blockInfo, &res.BlockInfo)
	return res, "", nil
}

func (c *ethConnector) getBlockInfoByHash(ctx context.Context, hash0xString string) (*blockInfoJSONRPC, error) {
	var blockInfo *blockInfoJSONRPC
	cached, ok := c.blockCache.Get(hash0xString)
	if ok {
		blockInfo = cached.(*blockInfoJSONRPC)
	}

	if blockInfo == nil {
		err := c.backend.Invoke(ctx, &blockInfo, "eth_getBlockByHash", hash0xString, false /* only the txn hashes */)
		if err != nil || blockInfo == nil {
			return nil, err
		}
		c.addToBlockCache(blockInfo)
	}

	return blockInfo, nil
}

func (c *ethConnector) BlockInfoByHash(ctx context.Context, req *ffcapi.BlockInfoByHashRequest) (*ffcapi.BlockInfoByHashResponse, ffcapi.ErrorReason, error) {

	blockInfo, err := c.getBlockInfoByHash(ctx, req.BlockHash)
	if err != nil {
		return nil, ffcapi.ErrorReason(""), err
	}
	if blockInfo == nil {
		return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
	}

	res := &ffcapi.BlockInfoByHashResponse{}
	transformBlockInfo(blockInfo, &res.BlockInfo)
	return res, "", nil

}
