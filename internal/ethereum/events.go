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

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

func (c *ethConnector) EventListenerVerifyOptions(ctx context.Context, standardOptions *ffcapi.ListenerOptions, customOptions *fftypes.JSONAny) (signature string, options fftypes.JSONAny, err error) {
	return "", "", nil
}

func (c *ethConnector) EventListenerAdd(ctx context.Context, req *ffcapi.EventListenerAddRequest) (*ffcapi.EventListenerAddResponse, ffcapi.ErrorReason, error) {
	return nil, "", nil
}

func (c *ethConnector) EventListenerRemove(ctx context.Context, req *ffcapi.EventListenerRemoveRequest) (*ffcapi.EventListenerRemoveResponse, ffcapi.ErrorReason, error) {
	return nil, "", nil
}

func (c *ethConnector) NewBlockHashes() <-chan *ffcapi.BlockHashEvent {
	return nil
}
