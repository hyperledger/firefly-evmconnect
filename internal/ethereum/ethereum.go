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
	"fmt"
	"math/big"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffresty"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-common/pkg/retry"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

type ethConnector struct {
	backend                    rpcbackend.Backend
	serializer                 *abi.Serializer
	gasEstimationFactor        *big.Float
	catchupPageSize            int64
	catchupThreshold           int64
	checkpointBlockGap         int64
	retry                      *retry.Retry
	eventBlockTimestamps       bool
	blockListener              *blockListener
	eventFilterPollingInterval time.Duration

	mux          sync.Mutex
	eventStreams map[fftypes.UUID]*eventStream
	blockCache   *lru.Cache
	txCache      *lru.Cache
}

func NewEthereumConnector(ctx context.Context, conf config.Section) (cc ffcapi.API, err error) {
	c := &ethConnector{
		eventStreams:               make(map[fftypes.UUID]*eventStream),
		catchupPageSize:            conf.GetInt64(EventsCatchupPageSize),
		catchupThreshold:           conf.GetInt64(EventsCatchupThreshold),
		checkpointBlockGap:         conf.GetInt64(EventsCheckpointBlockGap),
		eventBlockTimestamps:       conf.GetBool(EventsBlockTimestamps),
		eventFilterPollingInterval: conf.GetDuration(EventsFilterPollingInterval),
		retry: &retry.Retry{
			InitialDelay: conf.GetDuration(RetryInitDelay),
			MaximumDelay: conf.GetDuration(RetryMaxDelay),
			Factor:       conf.GetFloat64(RetryFactor),
		},
	}
	if c.catchupThreshold < c.catchupPageSize {
		log.L(ctx).Warnf("Catchup threshold %d must be at least as large as the catchup page size %d (overridden to %d)", c.catchupThreshold, c.catchupPageSize, c.catchupPageSize)
		c.catchupThreshold = c.catchupPageSize
	}
	c.blockCache, err = lru.New(conf.GetInt(BlockCacheSize))
	if err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgCacheInitFail, "block")
	}

	c.txCache, err = lru.New(conf.GetInt(TxCacheSize))
	if err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgCacheInitFail, "transaction")
	}

	if conf.GetString(ffresty.HTTPConfigURL) == "" {
		return nil, i18n.NewError(ctx, msgs.MsgMissingBackendURL)
	}
	c.gasEstimationFactor = big.NewFloat(conf.GetFloat64(ConfigGasEstimationFactor))


	httpClient, err := ffresty.New(ctx, conf)
	if err != nil {
		return nil, err
	}
	c.backend = rpcbackend.NewRPCClient(httpClient)

	c.serializer = abi.NewSerializer().SetByteSerializer(abi.HexByteSerializer0xPrefix)
	switch conf.Get(ConfigDataFormat) {
	case "map":
		c.serializer.SetFormattingMode(abi.FormatAsObjects)
	case "flat_array":
		c.serializer.SetFormattingMode(abi.FormatAsFlatArrays)
	case "self_describing":
		c.serializer.SetFormattingMode(abi.FormatAsSelfDescribingArrays)
	default:
		return nil, i18n.NewError(ctx, msgs.MsgBadDataFormat, conf.Get(ConfigDataFormat), "map,flat_array,self_describing")
	}
	c.serializer.SetDefaultNameGenerator(func(idx int) string {
		name := "output"
		if idx > 0 {
			name = fmt.Sprintf("%s%v", name, idx)
		}
		return name
	})

	c.blockListener = newBlockListener(ctx, c, conf)

	return c, nil
}

// WaitClosed can be called after cancelling all the contexts, to wait for everything to close down
func (c *ethConnector) WaitClosed() {
	if c.blockListener != nil {
		c.blockListener.waitClosed()
	}
	for _, s := range c.eventStreams {
		<-s.streamLoopDone
	}
}
