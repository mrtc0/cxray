package execve

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
	logger "github.com/mrtc0/cxray/pkg/logger"
	tracer "github.com/mrtc0/cxray/pkg/tracer"
	utils "github.com/mrtc0/cxray/pkg/utils"
)

const (
	source string = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>

#define ARGV_SIZE 128

enum event {
  EVENT_ARG,
  EVENT_RET,
};

struct data_t {
	u32 pid;
	u32 uid;
  char comm[TASK_COMM_LEN];
	char argv[ARGV_SIZE];
	enum event type;
	long retval;
  char container_id [9];
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
  bpf_probe_read(data->argv, sizeof(data->argv), ptr);
  events.perf_submit(ctx, data, sizeof(struct data_t));
  return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
  const char *argp = NULL;
  bpf_probe_read(&argp, sizeof(argp), ptr);
  if (argp) {
    return __submit_arg(ctx, (void *)(argp), data);
  }
  return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user * argv,
    const char __user *const __user * envp)
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
  data.pid = bpf_get_current_pid_tgid() >> 32;
  data.uid = bpf_get_current_uid_gid();
  data.type = EVENT_ARG;

  __submit_arg(ctx, (void *)filename, &data);


  #pragma unroll
  for (int i = 1; i < ARGV_SIZE; i++) {
    if (submit_arg(ctx, (void *)&argv[i], &data) == 0) {
      break;
    }
  }
  return 0;
}

int ret_syscall__execve(struct pt_regs *ctx)
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
  data.pid = bpf_get_current_pid_tgid() >> 32;
  data.uid = bpf_get_current_uid_gid();
	data.type = EVENT_RET;
	data.retval = PT_REGS_RC(ctx);

  events.perf_submit(ctx, &data, sizeof(struct data_t));
  return 0;
}
`
)

// EventType is EventArg or EventRet
type EventType uint32

const (
	// EventArg is EVENT_ARG in bpf program
	EventArg EventType = 0
	// EventRet is EVENT_RET in bpf program
	EventRet EventType = 1
	// ArgvSize is ARGV_SIZE in bpf program
	ArgvSize = 128
)

// execveEvent is saved a execve event (perfmap)
type execveEvent struct {
	// PID for process
	PID uint32
	// UID for process
	UID uint32
	// Comm is command name
	Comm [16]byte
	// Argv is argument for command
	Argv [ArgvSize]byte
	// Type is kprobe or kretprobe
	Type EventType
	// RetVal is return value
	RetVal int64
	// ContainerID is container id
	// This is the same ID as the UTS namespace of the process.
	ContainerID [9]byte
	// Pad is Padding
	Pad [3]byte
}

// execveTracer is reciver
// for save temporary data between kprobe to kretprobe
type execveTracer struct {
	module  *bpf.Module
	perfMap *bpf.PerfMap
	channel chan []byte
	argv    map[uint32]string
	comm    map[uint32]string
	logger  *logger.Logger
}

// Init is create a execveTracer
func Init(w io.Writer) tracer.Tracer {
	return &execveTracer{
		channel: make(chan []byte),
		argv:    map[uint32]string{},
		comm:    map[uint32]string{},
		logger:  logger.New(logger.Format(), logger.Output(w)),
	}
}

// Load is load to bpf program for execve syscall tracing
// And, generate BPF PerfMap
func (t *execveTracer) Load() error {
	t.module = bpf.NewModule(source, []string{})

	fnName := bpf.GetSyscallFnName("execve")

	// kprobe program name is must syscall__(SYSCALLNAME)
	// ref : https://github.com/iovisor/bcc/blob/149c1c8857652997622fc2a30747a60e0c9c17dc/src/cc/frontends/clang/b_frontend_action.cc#L671-L675
	kprobe, err := t.module.LoadKprobe("syscall__execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load do_sys_execve: %s\n", err)
		return err
	}

	if err := t.module.AttachKprobe(fnName, kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach do_sys_execve: %s\n", err)
		return err
	}

	kretprobe, err := t.module.LoadKprobe("ret_syscall__execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load ret_syscall__execve: %s\n", err)
		return err
	}

	if err := t.module.AttachKretprobe(fnName, kretprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach ret_syscall__execve: %s\n", err)
		return err
	}

	table := bpf.NewTable(t.module.TableId("events"), t.module)
	t.perfMap, err = bpf.InitPerfMap(table, t.channel)

	if err != nil {
		fmt.Errorf("Failed init PerfMap: %v", err)
		return err
	}

	return nil
}

// Watch is watch and logging to bpf event
func (t *execveTracer) Watch() error {
	var event execveEvent
	data := <-t.channel

	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
		return err
	}

	index := bytes.IndexByte(event.Argv[:], 0)
	if index <= -1 {
		index = ArgvSize
	}

	if event.Type == 0 {
		argv := strings.TrimSpace(string(event.Argv[:index]))
		if val, ok := t.argv[event.PID]; ok {
			t.argv[event.PID] = fmt.Sprintf("%s %s", val, argv)
		} else {
			t.argv[event.PID] = argv
		}
	}

	if event.Type == 1 {
		command := strings.Split(t.argv[event.PID], " ")
		comm := command[0]
		argv := strings.Join(command[1:], " ")

		username := utils.GetUsernameByUID(fmt.Sprint(event.UID))

		e := logger.EventLog{
			ContainerID: string(utils.TrimNullByte(event.ContainerID[:])),
			Event: logger.SyscallEventLog{
				Syscall: "execve",
				Data: map[string]string{
					"ret":  fmt.Sprint(event.RetVal),
					"pid":  fmt.Sprint(event.PID),
					"uid":  fmt.Sprint(event.UID),
					"user": username,
					"comm": comm,
					"argv": argv,
				},
			},
		}
		t.logger.Info("execve", e)
	}

	return nil
}

// Start is start this program
func (t *execveTracer) Start() {
	t.perfMap.Start()
}

// Stop is stop this program and close module
func (t *execveTracer) Stop() {
	t.perfMap.Stop()
	t.module.Close()
}

// Close is close module
func (t *execveTracer) Close() {
	t.module.Close()
}
