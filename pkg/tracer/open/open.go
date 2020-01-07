package open

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/mrtc0/cxray/pkg/logger"
	"github.com/mrtc0/cxray/pkg/tracer"
	"github.com/mrtc0/cxray/pkg/utils"
)

const (
	source string = `
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/fs.h>
#include <linux/ns_common.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>

struct data_t {
    u32 pid;
    u32 uid;
		int ret;
		char comm[TASK_COMM_LEN];
    char fname[70];
		char container_id [9];
    u32 flags; // EXTENDED_STRUCT_MEMBER
};

BPF_HASH(infotmp, u32, struct data_t);
BPF_PERF_OUTPUT(open_events);

int trace_entry(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode)
{
    struct data_t data = {};
		struct task_struct *task;

		task = (struct task_struct *)bpf_get_current_task();
		struct pid_namespace *pns = (struct pid_namespace *)task->nsproxy->pid_ns_for_children;

		// 0xEFFFFFFCU is initial host namespace id
		if (pns->ns.inum == 0xEFFFFFFCU) {
			return 0;
		}

		struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
		bpf_probe_read(&data.container_id, sizeof(data.container_id), (void *)uns->name.nodename);

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
		bpf_probe_read(&data.fname, sizeof(data.fname), (void *)filename);

		data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.flags = flags; // EXTENDED_STRUCT_MEMBER

    infotmp.update(&data.pid, &data);
    return 0;
}

int trace_return(struct pt_regs *ctx)
{
    struct data_t data = {};
		struct task_struct *task;
		u32 pid = bpf_get_current_pid_tgid() >> 32;

		task = (struct task_struct *)bpf_get_current_task();
		struct pid_namespace *pns = (struct pid_namespace *)task->nsproxy->pid_ns_for_children;

		// 0xEFFFFFFCU is initial host namespace id
		if (pns->ns.inum == 0xEFFFFFFCU) {
			return 0;
		}

		struct data_t *ptr = infotmp.lookup(&pid);

		if (ptr == 0) {
			return 0;
		}

		data = *ptr;
		data.ret = PT_REGS_RC(ctx);

    open_events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&pid);
    return 0;
}
	`
)

// TaskCommLen is TASK_COMM_LEN
var TaskCommLen = 16

// NameMax is NAME_MAX
// The definition of NAME_MAX is 255,
// but the size limit of Hash Map is 512.
// To exceed this, the value is reduced.
var NameMax = 70

// openEvent is saved a open event
type openEvent struct {
	// PID for process
	PID uint32
	// UID for process
	UID uint32
	// RetVal is return code
	RetVal uint32
	// Comm is command name
	Comm [16]byte
	// Fname is file name
	Fname [70]byte
	// ContainerID is container id
	// This is the same ID as the UTS namespace of the process.
	ContainerID [9]byte
	// Flags is EXTENDED_STRUCT_MEMBER
	Flags uint32
}

// openTracer is reciver
// for save temporary data between kprobe to kretprobe
type openTracer struct {
	module  *bpf.Module
	perfMap *bpf.PerfMap
	channel chan []byte
}

// Init is create openTracer
func Init() tracer.Tracer {
	return &openTracer{
		channel: make(chan []byte),
	}
}

// Load is load to bpf program for open syscall tracing
func (t *openTracer) Load() error {
	t.module = bpf.NewModule(source, []string{})

	fnName := "do_sys_open"

	kprobe, err := t.module.LoadKprobe("trace_entry")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_entry: %s\n", err)
		return err
	}

	if err := t.module.AttachKprobe(fnName, kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach trace_entry: %s\n", err)
		return err
	}

	kretprobe, err := t.module.LoadKprobe("trace_return")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_return: %s\n", err)
		return err
	}

	if err := t.module.AttachKretprobe(fnName, kretprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach trace_return: %s\n", err)
		return err
	}

	table := bpf.NewTable(t.module.TableId("open_events"), t.module)
	t.perfMap, err = bpf.InitPerfMap(table, t.channel)

	if err != nil {
		fmt.Errorf("Failed init PerfMap: %v", err)
		return err
	}

	return nil
}

// Wacth is watch and logging to bpf event
func (t *openTracer) Watch() (*logger.EventLog, error) {
	var event openEvent
	var eventLog logger.EventLog

	data := <-t.channel

	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
		return nil, err
	}

	index := bytes.IndexByte(event.Fname[:], 0)
	if index <= -1 {
		index = NameMax
	}
	fname := strings.TrimSpace(string(event.Fname[:index]))

	index = bytes.IndexByte(event.Comm[:], 0)
	if index <= -1 {
		index = TaskCommLen
	}
	comm := strings.TrimSpace(string(event.Comm[:index]))

	eventLog = logger.EventLog{
		ContainerID: string(utils.TrimNullByte(event.ContainerID[:])),
		Event: logger.Event{
			Name: "open",
			Data: map[string]string{
				"ret":   fmt.Sprint(event.RetVal),
				"pid":   fmt.Sprint(event.PID),
				"uid":   fmt.Sprint(event.UID),
				"comm":  comm,
				"fname": fname,
			},
		},
	}
	return &eventLog, nil
}

// Start is start this program
func (t *openTracer) Start() {
	t.perfMap.Start()
}

// Stop is stop this program and close module
func (t *openTracer) Stop() {
	t.perfMap.Stop()
	t.module.Close()
}

// Close is close module
func (t *openTracer) Close() {
	t.module.Close()
}
