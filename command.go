package main

import (
	"github.com/urfave/cli/v2"
)

var (
	nodeIdFlag = &cli.IntFlag{
		Name:     "id",
		Usage:    "id",
		Required: true,
	}
	nodeSubCommand = &cli.Command{
		Name:        "node",
		Usage:       "start pbft node",
		Description: "start pbft node",
		ArgsUsage:   "<id>",
		Flags: []cli.Flag{
			nodeIdFlag,
		},
		Action: func(c *cli.Context) error {
			nodeID := c.Int("id")
			server := NewServer(nodeID)
			server.Start()
			return nil
		},
	}
	clientIdFlag = &cli.IntFlag{
		Name:     "id",
		Usage:    "id",
		Required: true,
	}
	clientSubCommand = &cli.Command{
		Name:        "client",
		Usage:       "start pbft client",
		Description: "start pbft client",
		ArgsUsage:   "<id>",
		Flags: []cli.Flag{
			clientIdFlag,
		},
		Action: func(c *cli.Context) error {
			clientID := c.Int("id")
			client := NewClient(clientID)
			if clientID == 8 {
				client.Start()
			} else {
				println("destination")
			}
			return nil
		},
	}
	PBFTCommand = &cli.Command{
		Name:        "pbft",
		Usage:       "pbft commands",
		ArgsUsage:   "",
		Category:    "pbft Commands",
		Description: "",
		Subcommands: []*cli.Command{
			nodeSubCommand,
			clientSubCommand,
		},
	}
)
