package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	tracer "github.com/mrtc0/cxray/pkg/tracer"
	"github.com/mrtc0/cxray/pkg/tracer/execve"
	"github.com/mrtc0/cxray/pkg/tracer/listen"
	"github.com/mrtc0/cxray/pkg/tracer/open"
	"github.com/mrtc0/cxray/pkg/tracer/tcpv4connect"
	"gopkg.in/urfave/cli.v1"
)

func main() {
	app := cli.NewApp()

	app.Action = func(c *cli.Context) error {
		sig := make(chan os.Signal, 1)

		signal.Notify(sig, os.Interrupt)
		signal.Notify(sig, syscall.SIGTERM)

		tracer.Init()
		tracer.Tracers = map[string]tracer.Tracer{
			"execve":       execve.Init(os.Stdout),
			"open":         open.Init(os.Stdout),
			"tcpv4connect": tcpv4connect.Init(os.Stdout),
			"listen":       listen.Init(os.Stdout),
		}

		for _, t := range tracer.Tracers {
			err := t.Load()
			if err != nil {
				log.Fatal(err)
				t.Stop()
			}

			go func(t tracer.Tracer) {
				for {
					err := t.Watch()
					if err != nil {
						log.Fatal(err)
						t.Stop()
					}
				}
			}(t)

			t.Start()
		}

		<-sig
		for _, t := range tracer.Tracers {
			t.Stop()
		}
		return nil
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
