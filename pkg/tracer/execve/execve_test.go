package execve

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"

	tracer "github.com/mrtc0/cxray/pkg/tracer"
)

func TestLoad(t *testing.T) {
	tracer := Init(os.Stdout)

	err := tracer.Load()
	if err != nil {
		t.Error("Failed to load execve tracer")
	}

	tracer.Close()
}

func TestWatch(t *testing.T) {
	buf := &bytes.Buffer{}
	execveTracer := Init(buf)

	err := execveTracer.Load()
	if err != nil {
		fmt.Errorf("Failed to load execve tracer")
	}

	go func(execvetracer tracer.Tracer) {
		for {
			err := execvetracer.Watch()
			if err != nil {
				fmt.Errorf("Failed to watch execve tracer")
			}
		}
	}(execveTracer)

	execveTracer.Start()

	cmd := exec.Command("docker", "run", "-h", "test", "--rm", "alpine:latest", "sh", "-c", "'sleep 3; ls -al';")
	cmd.Start()
	cmd.Wait()

	execveTracer.Stop()

	output := buf.String()
	expect := regexp.MustCompile(`^{"data":{"container_id":"test","event":{"syscall":"execve","data":{"argv":"-c 'sleep 3; ls -al';","comm":"\/bin\/sh","pid":"\d+","ret":"0","uid":"0","user":"root"}}}`)
	if !expect.MatchString(output) {
		t.Errorf("Unexpected output.\nexpect regex: %#v,\n got: %s\n", expect, output)
	}
}
