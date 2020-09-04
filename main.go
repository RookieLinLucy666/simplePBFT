package main

import (
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v2"
)

func main() {
	fmt.Println("begin nano time:", time.Now().UnixNano())
	app := &cli.App{
		Commands: []*cli.Command{
			PBFTCommand,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Errorf("%s", err)
	}
}
