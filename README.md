# Workday Credentials CLI

The Cred CLI repository houses utility functions to build and visualize common credentialing objects and functions that are used in the Workday Credentialing Platform. The core object definitions implement data models defined in the W3C Verifiable Credentials and Decentralized Identifiers draft specifications. These functions and object definitions will be updated over time as those specifications continue to evolve.

## Go
This library uses Go version [1.13](https://golang.org/doc/go1.13).

## Mage
This library uses the [Mage](https://magefile.org/) build tool.

```
$ mage
Targets:
  build         builds the library.
  clean         deletes any build artifacts.
  test          runs unit tests without coverage.
```

## Commands

The CLI is built using [Cobra](https://github.com/spf13/cobra) and [Viper](https://github.com/spf13/viper). To run the `credwallet` first `go get github.com/workdaycredentials/credwallet` the project.

Commands are available for DIDs, Credentials, Schemas, Credential Definitions, Credential Revocations, and Presentation Requests and Responses.

```
Usage:
  credwallet [flags]
  credwallet [command]

Available Commands:
  cred         Work with Credentials
  creddef      Work with Credential Definitions
  did          Work with DIDs
  help         Help about any command
  presentation Generate, respond to, and verify presentation requests
  revocation   Work with Revocations
  schema       Work with Schemas

Flags:
      --config string   config file (default is $HOME/.credwallet.yaml)
  -h, --help            help for credwallet

Use "credwallet [command] --help" for more information about a command.
```