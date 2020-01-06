package tcpv4connect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/mrtc0/cxray/pkg/logger"
	"github.com/mrtc0/cxray/pkg/tracer"
	"github.com/mrtc0/cxray/pkg/utils"
)

const (
	source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>

struct data_t {
	u32 pid;
	u32 uid;
	u32 ret;
	char comm[TASK_COMM_LEN];
	char container_id[9];
	// unsigned __int128 daddr;
	__be32 daddr;
	__be32 saddr;
	unsigned short dport;
};

BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(tcp_v4_connect_events);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
		struct task_struct *task;
		u32 pid = bpf_get_current_pid_tgid();

		task = (struct task_struct *)bpf_get_current_task();
		struct pid_namespace *pns = (struct pid_namespace *)task->nsproxy->pid_ns_for_children;

		// 0xEFFFFFFCU is initial host namespace id
		if (pns->ns.inum == 0xEFFFFFFCU) {
			return 0;
		}

		currsock.update(&pid, &sk);
		return 0;
};


int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
		struct data_t data = {};
		struct task_struct *task;
		struct sock **skpp;

		int ret = PT_REGS_RC(ctx);
		u32 pid = bpf_get_current_pid_tgid();

		skpp = currsock.lookup(&pid);
		if (skpp == 0) {
			return 0;	// missed entry
		}

		task = (struct task_struct *)bpf_get_current_task();
		struct pid_namespace *pns = (struct pid_namespace *)task->nsproxy->pid_ns_for_children;

		// 0xEFFFFFFCU is initial host namespace id
		if (pns->ns.inum == 0xEFFFFFFCU) {
			return 0;
		}

		struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;

		data.ret = PT_REGS_RC(ctx);

		if (data.ret != 0) {
			// failed to send SYNC packet, may not have populated
			// socket __sk_common.{skc_rcv_saddr, ...}
			currsock.delete(&pid);
			return 0;
		}

		bpf_probe_read(&data.container_id, sizeof(data.container_id), (void *)uns->name.nodename);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
		data.pid = bpf_get_current_pid_tgid();
    data.uid = bpf_get_current_uid_gid();

		struct sock *skp = *skpp;
		data.daddr = skp->__sk_common.skc_daddr;
		data.dport = skp->__sk_common.skc_dport;
		data.saddr = skp->__sk_common.skc_rcv_saddr;

		tcp_v4_connect_events.perf_submit(ctx, &data, sizeof(data));

		currsock.delete(&pid);

		return 0;
}
	`
)

// TaskCommLen is TASK_COMM_LEN
var TaskCommLen = 16

type tcpV4ConnectEvent struct {
	PID         uint32
	UID         uint32
	Ret         uint32
	Comm        [16]byte
	ContainerID [9]byte
	_           [3]byte
	Daddr       uint32
	Saddr       uint32
	Dport       uint16
}

type tcpV4ConnectTracer struct {
	module  *bpf.Module
	perfMap *bpf.PerfMap
	channel chan []byte
}

// Init is initialize tcpV4ConnectTracer
func Init() tracer.Tracer {
	return &tcpV4ConnectTracer{
		channel: make(chan []byte),
	}
}

func (t *tcpV4ConnectTracer) Load() error {
	t.module = bpf.NewModule(source, []string{})

	fnName := "tcp_v4_connect"

	kprobe, err := t.module.LoadKprobe("kprobe__tcp_v4_connect")
	if err != nil {
		return err
	}

	if err := t.module.AttachKprobe(fnName, kprobe, -1); err != nil {
		return err
	}

	kretprobe, err := t.module.LoadKprobe("kretprobe__tcp_v4_connect")
	if err != nil {
		return err
	}

	if err := t.module.AttachKretprobe(fnName, kretprobe, -1); err != nil {
		return err
	}

	table := bpf.NewTable(t.module.TableId("tcp_v4_connect_events"), t.module)
	t.perfMap, err = bpf.InitPerfMap(table, t.channel)

	if err != nil {
		fmt.Errorf("Failed init PerfMap: %v", err)
		return err
	}

	return nil
}

// Wacth is watch and logging to bpf event
func (t *tcpV4ConnectTracer) Watch() (*logger.EventLog, error) {
	var event tcpV4ConnectEvent
	var eventLog logger.EventLog

	data := <-t.channel

	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
		return nil, err
	}

	index := bytes.IndexByte(event.Comm[:], 0)
	if index <= -1 {
		index = TaskCommLen
	}
	comm := strings.TrimSpace(string(event.Comm[:index]))

	eventLog = logger.EventLog{
		ContainerID: string(utils.TrimNullByte(event.ContainerID[:])),
		Event: logger.SyscallEventLog{
			Syscall: "tcp_v4_connect",
			Data: map[string]string{
				"ret":   fmt.Sprint(event.Ret),
				"pid":   fmt.Sprint(event.PID),
				"uid":   fmt.Sprint(event.UID),
				"comm":  comm,
				"saddr": utils.Uint2IPv4(event.Saddr).String(),
				"daddr": utils.Uint2IPv4(event.Daddr).String(),
				"dport": utils.Uint2Port(event.Dport),
			},
		},
	}

	return &eventLog, nil
}

// Start is start this program
func (t *tcpV4ConnectTracer) Start() {
	t.perfMap.Start()
}

// Stop is stop this program and close module
func (t *tcpV4ConnectTracer) Stop() {
	t.perfMap.Stop()
	t.module.Close()
}

// Close is close module
func (t *tcpV4ConnectTracer) Close() {
	t.module.Close()
}
