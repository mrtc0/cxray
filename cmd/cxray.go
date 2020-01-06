package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/mrtc0/cxray/pkg/logger"
	tracer "github.com/mrtc0/cxray/pkg/tracer"
	"github.com/mrtc0/cxray/pkg/tracer/execve"
	"github.com/mrtc0/cxray/pkg/tracer/listen"
	"github.com/mrtc0/cxray/pkg/tracer/open"
	"github.com/mrtc0/cxray/pkg/tracer/tcpv4connect"
	"gopkg.in/urfave/cli.v1"
)

func main() {
	app := cli.NewApp()
	l := logger.New(logger.Format(), logger.Output(os.Stdout))

	app.Action = func(c *cli.Context) error {
		l := logger.New(logger.Format(), logger.Output(os.Stdout))
		sig := make(chan os.Signal, 1)

		signal.Notify(sig, os.Interrupt)
		signal.Notify(sig, syscall.SIGTERM)

		tracer.Init()
		tracer.Tracers = map[string]tracer.Tracer{
			"execve":       execve.Init(),
			"open":         open.Init(),
			"tcpv4connect": tcpv4connect.Init(),
			"listen":       listen.Init(),
		}

		for _, t := range tracer.Tracers {
			err := t.Load()
			if err != nil {
				t.Stop()
				l.Fatal(err)
			}

			go func(t tracer.Tracer) {
				for {
					event, err := t.Watch()

					if event == nil {
						continue
					}

					if err != nil {
						t.Stop()
						l.Fatal(err)
					}

					l.Info("", *event)
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
		l.Fatal(err)
	}
}
