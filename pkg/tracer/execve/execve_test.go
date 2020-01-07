package execve

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"testing"

	logger "github.com/mrtc0/cxray/pkg/logger"
	tracer "github.com/mrtc0/cxray/pkg/tracer"
)

func TestLoad(t *testing.T) {
	tracer := Init()

	err := tracer.Load()
	if err != nil {
		t.Error("Failed to load execve tracer")
	}

	tracer.Close()
}

func TestWatch(t *testing.T) {
	execveTracer := Init()

	err := execveTracer.Load()
	if err != nil {
		fmt.Errorf("Failed to load execve tracer")
	}

	events := make(chan logger.EventLog, 20)

	go func(execvetracer tracer.Tracer) {
		for {
			event, err := execvetracer.Watch()
			if event == nil {
				continue
			}

			if err != nil {
				fmt.Errorf("Failed to watch execve tracer")
			}

			events <- *event
		}
	}(execveTracer)

	execveTracer.Start()

	cmd := exec.Command("sudo", "unshare", "--uts", "--pid", "--fork", "--", "ls -al")
	cmd.Start()
	cmd.Wait()

	execveTracer.Stop()

	close(events)

	s := make([]logger.EventLog, len(events))
	for i := range events {
		s = append(s, i)
	}

	b, err := json.Marshal(s)
	if err != nil {
		t.Errorf("Failed Marshal events struct: %s", err)
	}

	output := string(b)
	expect := regexp.MustCompile(`{"container_id":".*","event":{"name":"execve","data":{"argv":"-al","comm":"\/usr\/local\/sbin\/ls","pid":"\d+","ret":".*","uid":"0","user":"root"}}`)
	if !expect.MatchString(output) {
		t.Errorf("Unexpected output.\nexpect regex: %#v,\n got: %s\n", expect, output)
	}
}
