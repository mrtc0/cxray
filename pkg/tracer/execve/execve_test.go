package execve

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

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

	time.Sleep(3 * time.Second)

	cmd := exec.Command("sudo", "unshare", "--uts", "--pid", "--fork", "--", "ls -al")
	cmd.Start()
	cmd.Wait()

	execveTracer.Stop()

	output := buf.String()
	expect := regexp.MustCompile(`{"data":{"container_id":".*","event":{"syscall":"execve","data":{"argv":"-al","comm":"\/usr\/local\/sbin\/ls","pid":"\d+","ret":".*","uid":"0","user":"root"}}}`)
	if !expect.MatchString(output) {
		t.Errorf("Unexpected output.\nexpect regex: %#v,\n got: %s\n", expect, output)
	}
}
