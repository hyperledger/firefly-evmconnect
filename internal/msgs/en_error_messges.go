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

var ffe = func(key, translation string, statusHint ...int) i18n.ErrorMessageKey {
	return i18n.FFE(language.AmericanEnglish, key, translation, statusHint...)
}

//revive:disable
var (
	MsgRequestTypeNotImplemented = ffe("FF23010", "FFCAPI request '%s' not currently supported")
	MsgBlockNotAvailable         = ffe("FF23011", "Block not available")
	MsgReceiptNotAvailable       = ffe("FF23012", "Receipt not available for transaction '%s'")
	MsgUnmarshalABIFail          = ffe("FF23013", "Failed to parse method ABI: %s")
	MsgUnmarshalParamFail        = ffe("FF23014", "Failed to parse parameter %d: %s")
	MsgGasPriceError             = ffe("FF23015", `The gasPrice '%s' could not be parsed. Please supply a numeric string, or an object with 'gasPrice' field, or 'maxFeePerGas'/'maxPriorityFeePerGas' fields (EIP-1559)`)
	MsgInvalidOutputType         = ffe("FF23016", "Invalid output type: %s")
	MsgInvalidGasPrice           = ffe("FF23017", "Failed to parse gasPrice '%s': %s")
	MsgInvalidTXData             = ffe("FF23018", "Failed to parse transaction data as hex '%s': %s")
	MsgInvalidFromAddress        = ffe("FF23019", "Invalid 'from' address '%s': %s")
	MsgInvalidToAddress          = ffe("FF23020", "Invalid 'to' address '%s': %s")
	MsgRevertedWithMessage       = ffe("FF23021", "EVM reverted: %s")
	MsgRevertedRawRevertData     = ffe("FF23022", "EVM reverted: %s")
	MsgReturnDataInvalid         = ffe("FF23023", "EVM return data invalid: %s")
	MsgNotInitialized            = ffe("FF23024", "Not initialized")
	MsgMissingBackendURL         = ffe("FF23025", "URL must be set for the backend JSON/RPC endpoint")
	MsgBadVersion                = ffe("FF23026", "Bad FFCAPI Version '%s': %s")
	MsgUnsupportedVersion        = ffe("FF23027", "Unsupported FFCAPI Version '%s'")
	MsgUnsupportedRequestType    = ffe("FF23028", "Unsupported FFCAPI request type '%s'")
	MsgMissingRequestID          = ffe("FF23029", "Missing FFCAPI request id")
	MsgRPCRequestFailed          = ffe("FF23030", "Backend RPC request failed")
	MsgUnknownConnector          = ffe("FF23031", "Unknown connector type: '%s'")
	MsgBadDataFormat             = ffe("FF23032", "Unknown data format option '%s' supported: %s")
)
