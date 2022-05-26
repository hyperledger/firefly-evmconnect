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
	ConfigConnectorsType = ffc("config.connectors[].type", "The type of connector", "string")

	ConfigServerAddress      = ffc("config.connectors[].server.address", "Local address for the FFCAPI connector server to listen on", "string")
	ConfigServerPort         = ffc("config.connectors[].server.port", "Port for the FFCAPI connector server to listen on", "number")
	ConfigAPIPublicURL       = ffc("config.connectors[].server.publicURL", "External address callers should access API over", "string")
	ConfigServerReadTimeout  = ffc("config.connectors[].server.readTimeout", "The maximum time to wait when reading from an HTTP connection", "duration")
	ConfigServerWriteTimeout = ffc("config.connectors[].server.writeTimeout", "The maximum time to wait when writing to a HTTP connection", "duration")
	ConfigAPIShutdownTimeout = ffc("config.connectors[].server.shutdownTimeout", "The maximum amount of time to wait for any open HTTP requests to finish before shutting down the HTTP server", i18n.TimeDurationType)

	ConfigEthereumURL                 = ffc("config.connectors[].ethereum.url", "URL of JSON/RPC endpoint for the Ethereum node/gateway", "string")
	ConfigEthereumProxyURL            = ffc("config.connectors[].ethereum.proxy.url", "Optional HTTP proxy url", "string")
	ConfigEthereumDataFormat          = ffc("config.connectors[].ethereum.dataFormat", "Configure the JSON data format for query output and events", "map,flat_array,self_describing")
	ConfigEthereumGasEstimationFactor = ffc("config.connectors[].ethereum.gasEstimationFactor", "The factor to apply to the gas estimation to determine the gas limit", "float")
)
