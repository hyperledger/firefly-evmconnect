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

package msgs

import (
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"golang.org/x/text/language"
)

var ffc = func(key, translation string, fieldType string) i18n.ConfigMessageKey {
	return i18n.FFC(language.AmericanEnglish, key, translation, fieldType)
}

//revive:disable
var (
	ConfigEthereumURL                 = ffc("config.connector.url", "URL of JSON/RPC endpoint for the Ethereum node/gateway", "string")
	ConfigEthereumProxyURL            = ffc("config.connector.proxy.url", "Optional HTTP proxy url", "string")
	ConfigEthereumDataFormat          = ffc("config.connector.dataFormat", "Configure the JSON data format for query output and events", "map,flat_array,self_describing")
	ConfigEthereumGasEstimationFactor = ffc("config.connector.gasEstimationFactor", "The factor to apply to the gas estimation to determine the gas limit", "float")
)
