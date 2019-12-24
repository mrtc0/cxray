package tracer

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"
	logger "github.com/mrtc0/cxray/logger"
	utils "github.com/mrtc0/cxray/utils"
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

enum event {
  EVENT_ARG,
  EVENT_RET,
};

struct data_t {
	u32 pid;
	u32 uid;
  char container_id [9];
  char comm[TASK_COMM_LEN];
	char argv[128];
	char syscall [30];
	enum event type;
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
	char syscall[30] = "execve";

  task = (struct task_struct *)bpf_get_current_task();
	struct pid_namespace *pns = (struct pid_namespace *)task->nsproxy->pid_ns_for_children;

	// 0xEFFFFFFCU is initial host namespace id
	if (pns->ns.inum == 0xEFFFFFFCU) {
		return 0;
  }

	struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;

	bpf_probe_read(&data.container_id, sizeof(data.container_id), (void *)uns->name.nodename);
	bpf_probe_read(&data.syscall, sizeof(data.syscall), (void *)syscall);
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.pid = bpf_get_current_pid_tgid() >> 32;
  data.uid = bpf_get_current_uid_gid();
  data.type = EVENT_ARG;

  __submit_arg(ctx, (void *)filename, &data);


  #pragma unroll
  for (int i = 1; i < 128; i++) {
    if (submit_arg(ctx, (void *)&argv[i], &data) == 0) {
      break;
    }
  }
  return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
  struct data_t data = {};
  struct task_struct *task;
	char syscall[30] = "execve";

  task = (struct task_struct *)bpf_get_current_task();
	struct pid_namespace *pns = (struct pid_namespace *)task->nsproxy->pid_ns_for_children;

	// 0xEFFFFFFCU is initial host namespace id
	if (pns->ns.inum == 0xEFFFFFFCU) {
		return 0;
  }

	struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;

	bpf_probe_read(&data.container_id, sizeof(data.container_id), (void *)uns->name.nodename);
	bpf_probe_read(&data.syscall, sizeof(data.syscall), (void *)syscall);
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.pid = bpf_get_current_pid_tgid() >> 32;
  data.uid = bpf_get_current_uid_gid();
	data.type = EVENT_RET;

  events.perf_submit(ctx, &data, sizeof(struct data_t));
  return 0;
}
`
)

type EventType int32

const (
	EventArg EventType = iota
	EventRet
)

type ExecveEvent struct {
	Pid         uint32
	Uid         uint32
	ContainerID [9]byte
	Comm        [16]byte
	Argv        [128]byte
	Syscall     [30]byte
	Type        EventType
}

type Tracer struct {
	Logger *logger.Logger
}

func (tracer *Tracer) Trace() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	fnName := bpf.GetSyscallFnName("execve")

	kprobe, err := m.LoadKprobe("syscall__execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load do_sys_execve: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKprobe(fnName, kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach do_sys_execve: %s\n", err)
		os.Exit(1)
	}

	kretprobe, err := m.LoadKprobe("do_ret_sys_execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load do_ret_sys_execve: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKretprobe(fnName, kretprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach do_ret_sys_execve: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("events"), m)

	channel := make(chan []byte)
	perfMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		fmt.Errorf("init perf map failed: %v", err)
	}

	sig := make(chan os.Signal, 1)

	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)

	var result []map[string]interface{}

	go func() {
		m := make(map[uint32]string)
		for {
			var event ExecveEvent
			data := <-channel
			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
				fmt.Errorf("failed to decode received data: %v", err)
				os.Exit(1)
			}

			index := bytes.IndexByte(event.Argv[:], 0)
			if index <= -1 {
				index = 128
			}

			argv := strings.TrimSpace(string(event.Argv[:index]))

			if event.Type == 0 {
				if _, ok := m[event.Pid]; ok {
					m[event.Pid] = fmt.Sprintf("%s %s", m[event.Pid], argv)
				} else {
					m[event.Pid] = argv
				}
			}

			if event.Type == 256 {
				e := map[string]interface{}{
					"pid":          event.Pid,
					"uid":          event.Uid,
					"container_id": string(utils.TrimNullByte(event.ContainerID[:])),
					"comm":         m[event.Pid],
					"event":        string(utils.TrimNullByte(event.Syscall[:])),
				}
				tracer.Logger.Info("execve", e)
				result = append(result, e)
			}
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()

	outPutJson(result)
}

func outPutJson(result []map[string]interface{}) {
	s, err := json.Marshal(result)
	if err != nil {
		fmt.Println("Marshal error: %#v", result)
	}
	fmt.Println(string(s), "\n")
}
