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
	"time"

	"github.com/hyperledger/firefly-common/pkg/log"
)

func (c *ethConnector) doFailureDelay(ctx context.Context, failureCount int) bool {
	if failureCount <= 0 {
		return false
	}

	retryDelay := c.retry.InitialDelay
	for i := 0; i < (failureCount - 1); i++ {
		retryDelay = time.Duration(float64(retryDelay) * c.retry.Factor)
		if retryDelay > c.retry.MaximumDelay {
			retryDelay = c.retry.MaximumDelay
			break
		}
	}
	log.L(ctx).Debugf("Retrying after %.2f (failures=%d)", retryDelay.Seconds(), failureCount)
	select {
	case <-time.After(retryDelay):
		return false
	case <-ctx.Done():
		return true
	}
}
