package main

import (
	"github.com/workdaycredentials/credwallet/cli"
	_ "github.com/workdaycredentials/credwallet/cli/creddef"
	_ "github.com/workdaycredentials/credwallet/cli/credential"
	_ "github.com/workdaycredentials/credwallet/cli/did"
	_ "github.com/workdaycredentials/credwallet/cli/presentation"
	_ "github.com/workdaycredentials/credwallet/cli/revocation"
	_ "github.com/workdaycredentials/credwallet/cli/schema"
)

func main() {
	cli.Execute()
}
