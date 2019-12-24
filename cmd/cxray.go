package main

import (
	"log"
	"os"

	"github.com/mrtc0/cxray/logger"
	"github.com/mrtc0/cxray/tracer"
	"gopkg.in/urfave/cli.v1"
)

var (
	uid     []uint32
	runtime []string
)

func main() {
	app := cli.NewApp()

	app.Action = func(c *cli.Context) error {
		logger := logger.New()
		bpftracer := tracer.Tracer{Logger: logger}
		bpftracer.Trace()
		return nil
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
