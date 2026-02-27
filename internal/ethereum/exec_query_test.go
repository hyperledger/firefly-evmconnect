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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// buildErrorStringABI builds the raw ABI encoding for Error(string) with the given message bytes.
// The message can contain arbitrary bytes (including null bytes and nested ABI encodings).
func buildErrorStringABI(msgBytes []byte) []byte {
	offset := make([]byte, 32)
	binary.BigEndian.PutUint64(offset[24:], 0x20)
	length := make([]byte, 32)
	binary.BigEndian.PutUint64(length[24:], uint64(len(msgBytes)))
	paddedLen := ((len(msgBytes) + 31) / 32) * 32
	data := make([]byte, paddedLen)
	copy(data, msgBytes)

	result := make([]byte, 0, 4+32+32+paddedLen)
	result = append(result, defaultErrorID...)
	result = append(result, offset...)
	result = append(result, length...)
	result = append(result, data...)
	return result
}

const sampleExecQuery = `{
  "ffcapi": {
    "version": "v1.0.0",
    "id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
    "type": "exec_query"
  },
  "from": "0xb480F96c0a3d6E9e9a263e4665a39bFa6c4d01E8",
  "to": "0xe1a078b9e2b145d0a7387f09277c6ae1d9470771",
  "nonce": "222",
  "method": {
    "inputs": [
      {
        "internalType":" uint256",
        "name": "x",
        "type": "uint256"
      }
    ],
    "name":"set",
    "outputs":[
      {
        "internalType":"uint256",
        "name": "",
        "type": "uint256"
      },
      {
        "type": "string"
      }
    ],
    "stateMutability":"nonpayable",
    "type":"function"
  },
  "errors": [
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "x",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "y",
          "type": "uint256"
        }
      ],
      "name": "GreaterThanTen",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "x",
          "type": "string"
        }
      ],
      "name": "LessThanOne",
      "type": "error"
    }
  ],
  "params": [ 4276993775 ]
}`

func TestExecQueryOKResponse(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call",
		mock.MatchedBy(func(tx *ethsigner.Transaction) bool {
			assert.Equal(t, "0x60fe47b100000000000000000000000000000000000000000000000000000000feedbeef", tx.Data.String())
			return true
		}),
		"0x12345").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x00000000000000000000000000000000000000000000000000000000baadf00d0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000b68656c6c6f20776f726c64000000000000000000000000000000000000000000")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	req.BlockNumber = strPtr("0x12345")
	assert.NoError(t, err)

	res, reason, err := c.QueryInvoke(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)
	assert.JSONEq(t, `{"output": "3131961357", "output1":"hello world"}`, res.Outputs.String())

}

func TestExecQueryOKNilResponse(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call",
		mock.MatchedBy(func(tx *ethsigner.Transaction) bool {
			assert.Equal(t, "0x60fe47b100000000000000000000000000000000000000000000000000000000feedbeef", tx.Data.String())
			return true
		}),
		"latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	res, reason, err := c.QueryInvoke(ctx, &req)
	assert.NoError(t, err)
	assert.Empty(t, reason)
	assert.JSONEq(t, "null", res.Outputs.String())

}

func TestExecQueryCustomErrorRevertData(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x391ad4e000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000014")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	expectedError := i18n.NewError(ctx, msgs.MsgReverted, `GreaterThanTen("20", "20")`)
	assert.Equal(t, expectedError.Error(), err.Error())

}

func TestExecQueryCustomErrorRevertDataExceedsBalance(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002645524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e63650000000000000000000000000000000000000000000000000000")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	expectedError := i18n.NewError(ctx, msgs.MsgReverted, `ERC20: transfer amount exceeds balance`)
	assert.Equal(t, expectedError.Error(), err.Error())

}

func TestExecQueryCustomErrorRevertDataNotEnoughEther(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001a4e6f7420656e6f7567682045746865722070726f76696465642e000000000000")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	expectedError := i18n.NewError(ctx, msgs.MsgReverted, `Not enough Ether provided.`)
	assert.Equal(t, expectedError.Error(), err.Error())

}

func TestExecQueryCustomErrorRevertDataTransferFromZeroAddress(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002545524332303a207472616e736665722066726f6d20746865207a65726f2061646472657373000000000000000000000000000000000000000000000000000000")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	expectedError := i18n.NewError(ctx, msgs.MsgReverted, `ERC20: transfer from the zero address`)
	assert.Equal(t, expectedError.Error(), err.Error())

}

func TestExecQueryCustomErrorRevertDataBadOutput(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x053b20290000000000000000000000000000000000000000000000000000000000000020")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	expectedError := i18n.NewError(ctx, msgs.MsgReverted, `0x053b20290000000000000000000000000000000000000000000000000000000000000020`)
	assert.Equal(t, expectedError.Error(), err.Error())

}

func TestExecQueryCustomErrorBadRevertData(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Return(&rpcbackend.RPCError{Message: "pop", Data: "bad data"}).
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x053b20290000000000000000000000000000000000000000000000000000000000000020")
		})

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, _, err = c.QueryInvoke(ctx, &req)
	assert.Error(t, err)
	assert.Regexp(t, "pop", err)

}

func TestExecQueryBadErrorsABI(t *testing.T) {

	ctx, c, _, done := newTestConnector(t)
	defer done()

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	req.Errors = []*fftypes.JSONAny{fftypes.JSONAnyPtr(`[`)}
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonInvalidInputs, reason)

}

func TestExecQueryBadRevertData(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x08c379a000000000000000000000000000000000000000000000000000000000baadf00d")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Equal(t, ffcapi.ErrorReasonTransactionReverted, reason)
	assert.Regexp(t, "FF23021.*0x08c379a000000000000000000000000000000000000000000000000000000000baadf00d", err)

}

func TestExecQueryBadReturnData(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").
		Run(func(args mock.Arguments) {
			*(args[1].(*ethtypes.HexBytes0xPrefix)) = ethtypes.MustNewHexBytes0xPrefix("0x00000000000000000000000000000000000000000000000000000000baadf00d")
		}).
		Return(nil)

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(`{
			"ffcapi": {
				"version": "v1.0.0",
				"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
				"type": "exec_query"
			},
			"from": "0xb480F96c0a3d6E9e9a263e4665a39bFa6c4d01E8",
			"to": "0xe1a078b9e2b145d0a7387f09277c6ae1d9470771",
			"nonce": "222",
			"method": {
				"inputs": [],
				"name":"set",
				"outputs":[{"type":"uint256[10]"}],
				"stateMutability":"nonpayable",
				"type":"function"
			},
			"params": [ ]
		}`), &req)
	assert.NoError(t, err)

	_, reason, err := c.QueryInvoke(ctx, &req)
	assert.Empty(t, reason)
	assert.Regexp(t, "FF23023", err)

}

func TestExecQueryFailCall(t *testing.T) {

	ctx, c, mRPC, done := newTestConnector(t)
	defer done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_call", mock.Anything, "latest").Return(&rpcbackend.RPCError{Message: "pop"})

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(sampleExecQuery), &req)
	assert.NoError(t, err)
	_, _, err = c.QueryInvoke(ctx, &req)
	assert.Regexp(t, "pop", err)

}

func TestExecQueryFailBadToAddress(t *testing.T) {

	ctx, c, _, done := newTestConnector(t)
	defer done()

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(`{
		"ffcapi": {
			"version": "v1.0.0",
			"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
			"type": "exec_query"
		},
		"from": "0xb480F96c0a3d6E9e9a263e4665a39bFa6c4d01E8",
		"to": "wrong",
		"nonce": "222",
		"method": {
			"inputs": [],
			"name":"set",
			"outputs":[],
			"stateMutability":"nonpayable",
			"type":"function"
		},
		"params": [ ]
	}`), &req)
	assert.NoError(t, err)
	_, _, err = c.QueryInvoke(ctx, &req)
	assert.Regexp(t, "FF23020", err)

}

func TestProcessRevertReasonNestedErrorString(t *testing.T) {
	ctx, _, _, done := newTestConnector(t)
	defer done()

	// Outer Error(string) wrapping "outer: " + raw inner Error(string) ABI bytes.
	// Simulates: catch (bytes memory reason) { revert(string.concat("outer: ", string(reason))); }
	revertData := ethtypes.MustNewHexBytes0xPrefix(
		"0x08c379a00000000000000000000000000000000000000000000000000000000000000020" +
			"000000000000000000000000000000000000000000000000000000000000006b" +
			"6f757465723a20" +
			"08c379a0" +
			"0000000000000000000000000000000000000000000000000000000000000020" +
			"0000000000000000000000000000000000000000000000000000000000000013" +
			"696e6e6572206572726f72206d65737361676500000000000000000000000000" +
			"000000000000000000000000000000000000000000")

	result := processRevertReason(ctx, revertData, nil)
	assert.Equal(t, "outer: inner error message", result)
}

func TestProcessRevertReasonDoubleNestedErrorString(t *testing.T) {
	ctx, _, _, done := newTestConnector(t)
	defer done()

	// Three levels: Error("level1: " + Error("level2: " + Error("deepest error")))
	revertData := ethtypes.MustNewHexBytes0xPrefix(
		"0x08c379a0" +
			"0000000000000000000000000000000000000000000000000000000000000020" +
			"00000000000000000000000000000000000000000000000000000000000000cc" +
			"6c6576656c313a20" + // "level1: "
			"08c379a0" +
			"0000000000000000000000000000000000000000000000000000000000000020" +
			"000000000000000000000000000000000000000000000000000000000000006c" +
			"6c6576656c323a20" + // "level2: "
			"08c379a0" +
			"0000000000000000000000000000000000000000000000000000000000000020" +
			"000000000000000000000000000000000000000000000000000000000000000d" +
			"64656570657374206572726f720000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

	result := processRevertReason(ctx, revertData, nil)
	assert.Equal(t, "level1: level2: deepest error", result)
}

func TestProcessRevertReasonNestedCustomError(t *testing.T) {
	ctx, _, _, done := newTestConnector(t)
	defer done()

	// Define the custom error ABI first so we can use its real selector
	customErr := &abi.Entry{
		Type: abi.Error,
		Name: "MyCustomError",
		Inputs: abi.ParameterArray{
			{Type: "bytes"},
		},
	}
	customSelector := hex.EncodeToString(customErr.FunctionSelectorBytes())

	// Error("[404]01d - caught bytes:" + MyCustomError(0xdeadbeef) raw ABI bytes)
	revertData := ethtypes.MustNewHexBytes0xPrefix(
		"0x08c379a0" +
			"0000000000000000000000000000000000000000000000000000000000000020" +
			"000000000000000000000000000000000000000000000000000000000000007c" +
			"5b3430345d303164202d206361756768742062797465733a" + // "[404]01d - caught bytes:"
			customSelector +
			"0000000000000000000000000000000000000000000000000000000000000020" +
			"0000000000000000000000000000000000000000000000000000000000000004" +
			"deadbeef00000000000000000000000000000000000000000000000000000000" +
			"00000000")

	// With no error ABIs, the custom error can't be decoded —
	// the entire nested section is hex-encoded
	result := processRevertReason(ctx, revertData, nil)
	assert.True(t, strings.HasPrefix(result, "0x"))
	assert.NotContains(t, result, "\x00")

	// Now provide the custom error ABI so it CAN be decoded
	result = processRevertReason(ctx, revertData, []*abi.Entry{customErr})
	assert.Equal(t, `[404]01d - caught bytes:MyCustomError("deadbeef")`, result)
}

func TestProcessRevertReasonUnknownNestedBinaryFallback(t *testing.T) {
	ctx, _, _, done := newTestConnector(t)
	defer done()

	// Error("[404]01d - caught bytes:" + unknown error selector + binary payload)
	// The embedded selector ac8ae0 is NOT in our error ABIs, so the function
	// falls back to readable prefix + hex-encoded binary remainder.
	revertData := ethtypes.MustNewHexBytes0xPrefix("0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000007b5b3430345d303164202d2063617567687420627974" +
		"65733aac8ae000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004deadbeef000000000000000000000000000000000000000000000000000000000000000000")

	result := processRevertReason(ctx, revertData, nil)

	// Entire nested section is hex-encoded since no selector could be decoded
	assert.True(t, strings.HasPrefix(result, "0x"))
	assert.Contains(t, result, "deadbeef")
	assert.NotContains(t, result, "\x00")
}

func TestProcessRevertReasonPlainStringUnchanged(t *testing.T) {
	ctx, _, _, done := newTestConnector(t)
	defer done()

	// A normal Error(string) with no nested binary data should pass through unchanged
	revertData := ethtypes.MustNewHexBytes0xPrefix(
		"0x08c379a0" +
			"0000000000000000000000000000000000000000000000000000000000000020" +
			"000000000000000000000000000000000000000000000000000000000000001a" +
			"4e6f7420656e6f7567682045746865722070726f76696465642e000000000000")

	result := processRevertReason(ctx, revertData, nil)
	assert.Equal(t, "Not enough Ether provided.", result)
}

// ---- sanitizeBinaryString unit tests ----

func TestSanitizeBinaryStringEmpty(t *testing.T) {
	assert.Equal(t, "", sanitizeBinaryString(nil))
	assert.Equal(t, "", sanitizeBinaryString([]byte{}))
}

func TestSanitizeBinaryStringPureASCII(t *testing.T) {
	assert.Equal(t, "hello world", sanitizeBinaryString([]byte("hello world")))
}

func TestSanitizeBinaryStringTrailingNulls(t *testing.T) {
	// Any non-printable byte → entire input is hex-encoded
	assert.Equal(t, "0x736f6d65206572726f72000000", sanitizeBinaryString([]byte("some error\x00\x00\x00")))
}

func TestSanitizeBinaryStringPureBinary(t *testing.T) {
	assert.Equal(t, "0xdeadbeef", sanitizeBinaryString([]byte{0xde, 0xad, 0xbe, 0xef}))
}

func TestSanitizeBinaryStringPureNulls(t *testing.T) {
	assert.Equal(t, "0x000000", sanitizeBinaryString([]byte{0x00, 0x00, 0x00}))
}

func TestSanitizeBinaryStringSingleNullByte(t *testing.T) {
	assert.Equal(t, "0x00", sanitizeBinaryString([]byte{0x00}))
}

func TestSanitizeBinaryStringTextThenBinary(t *testing.T) {
	input := append([]byte("error: "), 0xde, 0xad, 0xbe, 0xef)
	assert.Equal(t, "0x6572726f723a20deadbeef", sanitizeBinaryString(input))
}

func TestSanitizeBinaryStringTextThenNulls(t *testing.T) {
	input := append([]byte("error: "), 0x00, 0x00)
	assert.Equal(t, "0x6572726f723a200000", sanitizeBinaryString(input))
}

func TestSanitizeBinaryStringControlCharAtStart(t *testing.T) {
	input := []byte{0x01, 'h', 'e', 'l', 'l', 'o'}
	assert.Equal(t, "0x0168656c6c6f", sanitizeBinaryString(input))
}

// ---- unwrapNestedRevertReasons unit tests ----

func TestUnwrapEmptyString(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", unwrapNestedRevertReasons(ctx, "", 0, nil))
}

func TestUnwrapPlainASCII(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "simple revert", unwrapNestedRevertReasons(ctx, "simple revert", 0, nil))
}

func TestUnwrapTrailingNulls(t *testing.T) {
	ctx := context.Background()
	// "some error" + trailing nulls → entire thing hex-encoded since it contains non-printable bytes
	result := unwrapNestedRevertReasons(ctx, "some error\x00\x00\x00", 0, nil)
	assert.Equal(t, "0x736f6d65206572726f72000000", result)
}

func TestUnwrapNestedErrorStringMalformedABI(t *testing.T) {
	ctx := context.Background()

	// Error(string) selector followed by garbage — can't ABI-decode, falls back to hex
	badData := "prefix:" + string(defaultErrorID) + "truncated"
	result := unwrapNestedRevertReasons(ctx, badData, 0, nil)
	// "prefix:" is pure ASCII so stays as text; the embedded section is hex-encoded
	assert.Equal(t, "prefix:0x08c379a07472756e6361746564", result)
}

func TestUnwrapDepthLimitReached(t *testing.T) {
	ctx := context.Background()

	innerABI := buildErrorStringABI([]byte("should not decode"))
	s := "prefix:" + string(innerABI)

	// At maxNestedRevertDepth, no further decoding happens — entire string hex-encoded
	result := unwrapNestedRevertReasons(ctx, s, maxNestedRevertDepth, nil)
	assert.True(t, strings.HasPrefix(result, "0x"))
	assert.NotEqual(t, "prefix:should not decode", result)
	assert.NotContains(t, result, "\x00")
}

func TestUnwrapDepthLimitMinusOneStillDecodes(t *testing.T) {
	ctx := context.Background()

	innerABI := buildErrorStringABI([]byte("decoded at limit"))
	s := "prefix:" + string(innerABI)

	result := unwrapNestedRevertReasons(ctx, s, maxNestedRevertDepth-1, nil)
	assert.Equal(t, "prefix:decoded at limit", result)
}

func TestUnwrapErrorStringSelectorPickedOverCustomWhenEarlier(t *testing.T) {
	ctx := context.Background()

	customErr := &abi.Entry{
		Type:   abi.Error,
		Name:   "CustomErr",
		Inputs: abi.ParameterArray{{Type: "uint256"}},
	}
	customSel := customErr.FunctionSelectorBytes()

	innerErrorABI := buildErrorStringABI([]byte("decoded-inner"))
	// Error(string) appears first, then the custom selector later
	s := "first:" + string(innerErrorABI) + "\x00\x00" + string(customSel) + "\x00\x00"
	result := unwrapNestedRevertReasons(ctx, s, 0, []*abi.Entry{customErr})
	assert.Equal(t, "first:decoded-inner", result)
}

func TestUnwrapCustomSelectorPickedOverErrorStringWhenEarlier(t *testing.T) {
	ctx := context.Background()

	customErr := &abi.Entry{
		Type:   abi.Error,
		Name:   "EarlyErr",
		Inputs: abi.ParameterArray{{Type: "uint256"}},
	}
	customSel := customErr.FunctionSelectorBytes()

	// Build a custom error encoding: selector + one uint256 word (value=42)
	arg := make([]byte, 32)
	binary.BigEndian.PutUint64(arg[24:], 42)
	customEncoded := append(customSel, arg...)

	innerErrorABI := buildErrorStringABI([]byte("late-error"))
	// Custom selector appears before the Error(string) selector
	s := "head:" + string(customEncoded) + "middle:" + string(innerErrorABI)
	result := unwrapNestedRevertReasons(ctx, s, 0, []*abi.Entry{customErr})
	assert.Equal(t, `head:EarlyErr("42")`, result)
}

func TestUnwrapCustomErrorMultipleParams(t *testing.T) {
	ctx := context.Background()

	customErr := &abi.Entry{
		Type: abi.Error,
		Name: "DetailedError",
		Inputs: abi.ParameterArray{
			{Type: "uint256", Name: "code"},
			{Type: "uint256", Name: "extra"},
		},
	}
	customSel := customErr.FunctionSelectorBytes()

	arg1 := make([]byte, 32)
	binary.BigEndian.PutUint64(arg1[24:], 404)
	arg2 := make([]byte, 32)
	binary.BigEndian.PutUint64(arg2[24:], 999)
	customEncoded := append(customSel, arg1...)
	customEncoded = append(customEncoded, arg2...)

	s := "err:" + string(customEncoded)
	result := unwrapNestedRevertReasons(ctx, s, 0, []*abi.Entry{customErr})
	assert.Equal(t, `err:DetailedError("404", "999")`, result)
}

func TestUnwrapCustomErrorDecodeFails(t *testing.T) {
	ctx := context.Background()

	customErr := &abi.Entry{
		Type:   abi.Error,
		Name:   "BadErr",
		Inputs: abi.ParameterArray{{Type: "uint256"}, {Type: "uint256"}},
	}
	customSel := customErr.FunctionSelectorBytes()

	// Only 1 word of data but the error needs 2 — decode will fail
	arg := make([]byte, 32)
	binary.BigEndian.PutUint64(arg[24:], 1)
	truncated := append(customSel, arg...)

	s := "prefix:" + string(truncated)
	result := unwrapNestedRevertReasons(ctx, s, 0, []*abi.Entry{customErr})
	// "prefix:" is clean ASCII, embedded section is hex-encoded
	assert.True(t, strings.HasPrefix(result, "prefix:0x"))
	assert.Contains(t, result, hex.EncodeToString(customSel))
}

func TestUnwrapPureBinaryNoSelector(t *testing.T) {
	ctx := context.Background()

	s := string([]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00})
	result := unwrapNestedRevertReasons(ctx, s, 0, nil)
	assert.Equal(t, "0xdeadbeef0000", result)
}

func TestUnwrapNilErrorAbis(t *testing.T) {
	ctx := context.Background()

	innerABI := buildErrorStringABI([]byte("works with nil abis"))
	s := "check:" + string(innerABI)
	result := unwrapNestedRevertReasons(ctx, s, 0, nil)
	assert.Equal(t, "check:works with nil abis", result)
}

func TestUnwrapEmptyErrorAbis(t *testing.T) {
	ctx := context.Background()

	innerABI := buildErrorStringABI([]byte("works with empty abis"))
	s := "check:" + string(innerABI)
	result := unwrapNestedRevertReasons(ctx, s, 0, []*abi.Entry{})
	assert.Equal(t, "check:works with empty abis", result)
}

func TestUnwrapNullBytesBetweenTextAndSelector(t *testing.T) {
	ctx := context.Background()

	innerABI := buildErrorStringABI([]byte("inner"))
	s := "text\x00\x00\x00" + string(innerABI)
	result := unwrapNestedRevertReasons(ctx, s, 0, nil)
	// Prefix "text\x00\x00\x00" has non-printable bytes → entirely hex-encoded
	assert.True(t, strings.HasPrefix(result, "0x"))
	assert.True(t, strings.HasSuffix(result, "inner"))
}

func TestUnwrapNestedWithTrailingGarbage(t *testing.T) {
	ctx := context.Background()

	// Inner Error(string) followed by trailing null padding (simulates ABI padding from outer encoding)
	innerABI := buildErrorStringABI([]byte("real message"))
	s := "prefix:" + string(innerABI) + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	result := unwrapNestedRevertReasons(ctx, s, 0, nil)
	assert.Equal(t, "prefix:real message", result)
}

func TestExecQueryFailBadToParams(t *testing.T) {

	ctx, c, _, done := newTestConnector(t)
	defer done()

	var req ffcapi.QueryInvokeRequest
	err := json.Unmarshal([]byte(`{
		"ffcapi": {
			"version": "v1.0.0",
			"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
			"type": "exec_query"
		},
		"from": "0xb480F96c0a3d6E9e9a263e4665a39bFa6c4d01E8",
		"to": "wrong",
		"nonce": "222",
		"method": {
			"inputs": [],
			"name":"set",
			"outputs":[],
			"stateMutability":"nonpayable",
			"type":"function"
		},
		"params": [ "unexpected extra param" ]
	}`), &req)
	assert.NoError(t, err)
	_, _, err = c.QueryInvoke(ctx, &req)
	assert.Regexp(t, "FF22037", err)

}
