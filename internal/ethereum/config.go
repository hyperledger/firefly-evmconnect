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
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffresty"
)

const (
	ConfigGasEstimationFactor   = "gasEstimationFactor"
	ConfigDataFormat            = "dataFormat"
	BlockPollingInterval        = "blockPollingInterval"
	BlockCacheSize              = "blockCacheSize"
	BlockCacheTTL               = "blockCacheTTL"
	EventsCatchupPageSize       = "events.catchupPageSize"
	EventsCatchupThreshold      = "events.catchupThreshold"
	EventsCheckpointBlockGap    = "events.checkpointBlockGap"
	EventsBlockTimestamps       = "events.blockTimestamps"
	EventsFilterPollingInterval = "events.filterPollingInterval"
	RetryInitDelay              = "retry.initialDelay"
	RetryMaxDelay               = "retry.maxDelay"
	RetryFactor                 = "retry.factor"
)

const (
	DefaultListenerPort        = 5102
	DefaultGasEstimationFactor = 1.5

	DefaultCatchupPageSize          = 5000
	DefaultEventsCatchupThreshold   = 5000
	DefaultEventsCheckpointBlockGap = 50

	DefaultRetryInitDelay   = "100ms"
	DefaultRetryMaxDelay    = "30s"
	DefaultRetryDelayFactor = 2.0
)

func InitConfig(conf config.Section) {
	ffresty.InitConfig(conf)
	conf.AddKnownKey(BlockCacheSize, 250)
	conf.AddKnownKey(BlockCacheTTL, "5m")
	conf.AddKnownKey(BlockPollingInterval, "1s")
	conf.AddKnownKey(ConfigDataFormat, "map")
	conf.AddKnownKey(ConfigGasEstimationFactor, DefaultGasEstimationFactor)
	conf.AddKnownKey(EventsBlockTimestamps, true)
	conf.AddKnownKey(EventsFilterPollingInterval, "1s")
	conf.AddKnownKey(EventsCatchupPageSize, DefaultCatchupPageSize)
	conf.AddKnownKey(EventsCatchupThreshold, DefaultEventsCatchupThreshold)
	conf.AddKnownKey(EventsCheckpointBlockGap, DefaultEventsCheckpointBlockGap)
	conf.AddKnownKey(RetryFactor, DefaultRetryDelayFactor)
	conf.AddKnownKey(RetryInitDelay, DefaultRetryInitDelay)
	conf.AddKnownKey(RetryMaxDelay, DefaultRetryMaxDelay)
}
