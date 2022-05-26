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
	"encoding/json"

	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

func (c *ethConnector) createBlockListener(ctx context.Context, payload []byte) (interface{}, ffcapi.ErrorReason, error) {

	var req ffcapi.CreateBlockListenerRequest
	err := json.Unmarshal(payload, &req)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	var listenerID ethtypes.HexInteger
	err = c.backend.Invoke(ctx, &listenerID, "eth_newBlockFilter")
	if err != nil {
		return nil, "", err
	}

	return &ffcapi.CreateBlockListenerResponse{
		ListenerID: listenerID.String(),
	}, "", nil

}
