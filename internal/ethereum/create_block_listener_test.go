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
	"fmt"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const sampleCreateBlockListener = `{
	"ffcapi": {
		"version": "v1.0.0",
		"id": "904F177C-C790-4B01-BDF4-F2B4E52E607E",
		"type": "create_block_listener"
	}
}`

func TestCreateBlockListenerOK(t *testing.T) {

	c, mRPC := newTestConnector(t)
	ctx := context.Background()

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newBlockFilter").
		Return(nil).
		Run(func(args mock.Arguments) {
			(args[1].(*ethtypes.HexInteger)).BigInt().SetString("12345", 10)
		})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Maybe()

	iRes, reason, err := c.createBlockListener(ctx, []byte(sampleCreateBlockListener))
	assert.NoError(t, err)
	assert.Empty(t, reason)

	res := iRes.(*ffcapi.CreateBlockListenerResponse)
	assert.Equal(t, "0x3039", res.ListenerID)

}

func TestCreateBlockListenerFail(t *testing.T) {

	c, mRPC := newTestConnector(t)
	ctx := context.Background()

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newBlockFilter").
		Return(fmt.Errorf("pop"))

	iRes, reason, err := c.createBlockListener(ctx, []byte(sampleCreateBlockListener))
	assert.Regexp(t, "pop", err)
	assert.Empty(t, reason)
	assert.Nil(t, iRes)

}

func TestCreateBlockListenerBadPayload(t *testing.T) {

	c, _ := newTestConnector(t)
	ctx := context.Background()

	iRes, reason, err := c.createBlockListener(ctx, []byte("!json"))
	assert.Regexp(t, "invalid", err)
	assert.Equal(t, ffcapi.ErrorReasonInvalidInputs, reason)
	assert.Nil(t, iRes)

}
