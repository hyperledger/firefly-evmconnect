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

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/ethereum"
	"github.com/hyperledger/firefly-evmconnect/internal/ffconnector"
	"github.com/hyperledger/firefly-evmconnect/internal/ffcserver"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var sigs = make(chan os.Signal, 1)

var rootCmd = &cobra.Command{
	Use:   "evmconnect",
	Short: "Hyperledger FireFly Connector for EVM based blockchains",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		return run()
	},
}

var cfgFile string

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "f", "", "config file")
	rootCmd.AddCommand(versionCommand())
	rootCmd.AddCommand(configCommand())
}

func Execute() error {
	return rootCmd.Execute()
}

var connectors config.ArraySection

func initConfig() {
	config.RootConfigReset()

	// Read the configuration
	connectors = config.RootArray(ConfigConnectors)
	connectors.AddKnownKey(ConfigConnectorType)

	serverConf := connectors.SubSection(ConfigConnectorServer)
	corsConf := config.RootSection(ConfigCORS)
	ffcserver.InitConfig(serverConf, corsConf)

	ethereumConf := connectors.SubSection(ConfigConnectorEthereum)
	ethereum.InitConfig(ethereumConf)
}

func run() error {

	initConfig()
	err := config.ReadConfig("evmconnect", cfgFile)

	// Setup logging after reading config (even if failed), to output header correctly
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	ctx = log.WithLogger(ctx, logrus.WithField("pid", fmt.Sprintf("%d", os.Getpid())))
	ctx = log.WithLogger(ctx, logrus.WithField("prefix", "evmconnect"))

	config.SetupLogging(ctx)

	// Deferred error return from reading config
	if err != nil {
		cancelCtx()
		return i18n.WrapError(ctx, err, i18n.MsgConfigFailed)
	}

	// Setup signal handling to cancel the context, which shuts down the API Server
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.L(ctx).Infof("Shutting down due to %s", sig.String())
		cancelCtx()
	}()

	// Initialize the server for each of the connectors defined
	numConnectors := connectors.ArraySize()
	serversDone := make(chan error, numConnectors)
	servers := make([]ffcserver.Server, numConnectors)
	for i := 0; i < numConnectors; i++ {
		baseConnectorConf := connectors.ArrayEntry(i)
		serverConnectorConf := baseConnectorConf.SubSection(ConfigConnectorServer)
		connectorType := baseConnectorConf.GetString(ConfigConnectorType)
		childConnectorConf := baseConnectorConf.SubSection(connectorType)
		var c ffconnector.Connector
		switch connectorType {
		case ConfigConnectorEthereum:
			c = ethereum.NewEthereumConnector(childConnectorConf)
		default:
			return i18n.NewError(ctx, msgs.MsgUnknownConnector, connectorType)
		}
		err := c.Init(ctx, childConnectorConf)
		if err == nil {
			servers[i] = ffcserver.NewServer(serverConnectorConf, c)
			err = servers[i].Init(ctx, serverConnectorConf, config.RootSection(ConfigCORS))
		}
		if err != nil {
			return err
		}
	}
	// Start all the servers
	for _, s := range servers {
		go runServer(s, serversDone)
	}
	// Whenever the first one stops (due to ctrl+c or error), stop them all and exit
	var firstError error
	for range servers {
		err = <-serversDone
		cancelCtx()
		if firstError == nil {
			firstError = err
		}
	}
	return firstError
}

func runServer(server ffcserver.Server, done chan error) {
	err := server.Start()
	if err != nil {
		done <- err
		return
	}
	done <- server.WaitStopped()
}
