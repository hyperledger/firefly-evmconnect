// Copyright © 2021 Kaleido, Inc.
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

package cmd

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hyperledger/firefly-evmconnect/mocks/ffcservermocks"
	"github.com/stretchr/testify/assert"
)

const configDir = "../test/data/config"

func TestRunOK(t *testing.T) {

	rootCmd.SetArgs([]string{"-f", "../test/firefly.evmconnect.yaml"})
	defer rootCmd.SetArgs([]string{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		err := Execute()
		if err != nil {
			assert.Regexp(t, "context deadline", err)
		}
	}()

	time.Sleep(10 * time.Millisecond)
	sigs <- os.Kill

	<-done

}

func TestRunUnknownConnector(t *testing.T) {

	rootCmd.SetArgs([]string{"-f", "../test/unknown-connector.evmconnect.yaml"})
	defer rootCmd.SetArgs([]string{})

	err := Execute()
	assert.Regexp(t, "FF23031", err)

}

func TestRunBadConfig(t *testing.T) {

	rootCmd.SetArgs([]string{"-f", "../test/bad-config.evmconnect.yaml"})
	defer rootCmd.SetArgs([]string{})

	err := Execute()
	assert.Regexp(t, "FF00101", err)

}

func TestRunFailStartup(t *testing.T) {
	rootCmd.SetArgs([]string{"-f", "../test/bad-server.evmconnect.yaml"})
	defer rootCmd.SetArgs([]string{})

	err := Execute()
	assert.Regexp(t, "FF00151", err)

}

func TestRunFailServer(t *testing.T) {

	s := &ffcservermocks.Server{}
	s.On("Start").Return(fmt.Errorf("pop"))
	done := make(chan error, 1)
	runServer(s, done)
	assert.Regexp(t, <-done, "pop")

}

func TestRunServerReturnErr(t *testing.T) {

	s := &ffcservermocks.Server{}
	s.On("Start").Return(nil)
	done := make(chan error, 1)
	s.On("WaitStopped").Return(fmt.Errorf("pop"))
	runServer(s, done)
	assert.Regexp(t, <-done, "pop")

}
