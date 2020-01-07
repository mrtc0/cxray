package listen

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
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>

#if defined(__LITTLE_ENDIAN)
#define bcc_be32_to_cpu(x) ((u32)(__builtin_bswap32)((x)))
#define bcc_be64_to_cpu(x) ((u64)(__builtin_bswap64)((x)))
#elif defined(__BIG_ENDIAN)
#define bcc_be32_to_cpu(x) (x)
#define bcc_be64_to_cpu(x) (x)
#else
#error Host endianness not defined
#endif

struct data_t {
	u32 pid;
	u32 uid;
	char comm[TASK_COMM_LEN];
  u64 proto;    // familiy << 16 | type
  u64 lport;    // use only 16 bits
  u64 laddr[2]; // IPv4: store in laddr[0]
	char container_id[9];
};

BPF_PERF_OUTPUT(listen_event);

int trace__inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog)
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
	data.pid = bpf_get_current_pid_tgid();

	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
  u16 family = sk->__sk_common.skc_family;
  data.proto = family << 16 | SOCK_STREAM;

	bpf_probe_read(&data.lport, sizeof(u16), &(inet->inet_sport));
	data.lport = ntohs(data.lport);

	if (family == AF_INET) {
		bpf_probe_read(data.laddr, sizeof(u32), &(inet->inet_rcv_saddr));
		data.laddr[0] = bcc_be32_to_cpu(data.laddr[0]);
	} else if (family == AF_INET6) {
		bpf_probe_read(data.laddr, sizeof(data.laddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		data.laddr[0] = bcc_be64_to_cpu(data.laddr[0]);
    data.laddr[1] = bcc_be64_to_cpu(data.laddr[1]);
  }

	listen_event.perf_submit(ctx, &data, sizeof(data));
	return 0;
}
	`
)

var TaskCommLen = 16

type inetListenEvent struct {
	PID         uint32
	UID         uint32
	Comm        [16]byte
	Proto       uint64
	ListenPort  uint64
	ListenAddr  [4]byte
	ContainerID [9]byte
	_           [7]byte
}

type inetListenTracer struct {
	module  *bpf.Module
	perfMap *bpf.PerfMap
	channel chan []byte
}

func Init() tracer.Tracer {
	return &inetListenTracer{
		channel: make(chan []byte),
	}
}

func (t *inetListenTracer) Load() error {
	t.module = bpf.NewModule(source, []string{})

	fnName := "inet_listen"

	kprobe, err := t.module.LoadKprobe("trace__inet_listen")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace__inet_listen: %s\n", err)
		return err
	}

	if err := t.module.AttachKprobe(fnName, kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach %s trace__inet_listen: %s\n", fnName, err)
		return err
	}

	table := bpf.NewTable(t.module.TableId("listen_event"), t.module)
	t.perfMap, err = bpf.InitPerfMap(table, t.channel)

	if err != nil {
		fmt.Errorf("Failed init PerfMap: %v", err)
		return err
	}

	return nil
}

func (t *inetListenTracer) Watch() (*logger.EventLog, error) {
	var event inetListenEvent
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

	proto_family := event.Proto & 0xff

	protocol := "unknown"

	switch proto_family {
	case 1:
		protocol = "tcp" // SOCK_STREAM
	case 2:
		protocol = "udp" // SOCK_DGRAM
	default:
		protocol = "unknown"
	}

	eventLog = logger.EventLog{
		ContainerID: string(utils.TrimNullByte(event.ContainerID[:])),
		Event: logger.Event{
			Name: "inet_listen",
			Data: map[string]string{
				"pid":         fmt.Sprint(event.PID),
				"uid":         fmt.Sprint(event.UID),
				"comm":        comm,
				"protocol":    protocol,
				"listen_port": fmt.Sprint(event.ListenPort),
				"listen_addr": fmt.Sprint(utils.ByteArrayToIPv4(event.ListenAddr)),
			},
		},
	}

	return &eventLog, nil
}

// Start is start this program
func (t *inetListenTracer) Start() {
	t.perfMap.Start()
}

// Stop is stop this program and close module
func (t *inetListenTracer) Stop() {
	t.perfMap.Stop()
	t.module.Close()
}

// Close is close module
func (t *inetListenTracer) Close() {
	t.module.Close()
}
