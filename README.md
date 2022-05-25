[![codecov](https://codecov.io/gh/hyperledger/firefly-evmconnect/branch/main/graph/badge.svg?token=OEI8A08P0R)](https://codecov.io/gh/hyperledger/firefly-evmconnect)
[![Go Reference](https://pkg.go.dev/badge/github.com/hyperledger/firefly-evmconnect.svg)](https://pkg.go.dev/github.com/hyperledger/firefly-evmconnect)

# Hyperledger FireFly EVM Connector

This repo provides a reference implementation of the FireFly Connector API (FFCAPI)
for EVM Based blockchains.

See the [Hyperledger Firefly Documentation](https://hyperledger.github.io/firefly/overview/public_vs_permissioned.html#firefly-architecture-for-public-chains)
and the [FireFly Transaction Manager](https://github.com/hyperledger/firefly-transaction-manager) repository for
more information.

> Also see [firefly-ethconnect](https://github.com/hyperledger/firefly-ethconnect) for the hardened
> connector optimized for private Ethereum sidechains, optimized for finality assured consensus
> algorithms and throughput.

# License

Apache 2.0

## ABI Encoding

A key responsibility of the FFCAPI connector is to map from developer friendly JSON inputs/outputs
down to the binary encoding of the blockchain.

This repo uses the Apache 2.0 RLP encoding/decoding utilities from the
[firefly-signer](https://github.com/hyperledger/firefly-signer) repository.

## Configuration

For a full list of configuration options see [config.md](./config.md)

## Example configuration

```yaml
connectors:
connectors:
- type: ethereum
  server:
    port: 5102
  ethereum:
    url: http://localhost:8545
```


