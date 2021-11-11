package main

import (
	"github.com/docopt/docopt-go"
	mfaws "github.com/ingenieux/mf-aws"
)

func main() {
	usage := `
mf-aws.

Usage:
  mf-aws PROFILE
`

	arguments, _ := docopt.ParseDoc(usage)

	engine, err := mfaws.NewMFEngine(arguments["PROFILE"].(string))

	if nil != err {
		panic(err)
	}

	err = engine.Execute()

	if nil != err {
		panic(err)
	}
}
