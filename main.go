package main

import (
	"os"

	"github.com/acidghost/fcp/internal/cli"
)

var (
	buildVersion string
	buildCommit  string
	buildDate    string
)

func main() {
	os.Exit(cli.Execute(cli.BuildInfo{
		Version: buildVersion,
		Commit:  buildCommit,
		Date:    buildDate,
	}))
}
