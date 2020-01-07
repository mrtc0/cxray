# cxray

[![Build Status](https://mrtc0.semaphoreci.com/badges/cxray/branches/master.svg)](https://semaphoreci.com/mrtc0/cxray)

cxray is a tool for profiling security events in containers.  
It can create a white list of events(running processes, opendfile and binaries, destination HTTP Requests) in container, which is useful for creating rules for other tools(e.g. falco).

# Background

Container security tools should be able to automatically profile containerized apps using behavioral learning and build.  
According to [NIST.SP.800-19](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf), should monitoring the following events:

 * Invalid or unexpected process execution,
 * Invalid or unexpected system calls,
 * Changes to protected configuration files and binaries,
 * Writes to unexpected locations and file types,
 * Creation of unexpected network listeners,
 * Traffic sent to unexpected network destinations, and
 * Malware storage or execution.

cxray can profiling these events. Executes in a test environment and records events in the container, and can be used for monitoring rules.  

# Install

Download binary from [releases page](https://github.com/mrtc0/cxray/releases).  

# Example

```shell
$ sudo ./cxray > log.json

$ docker run --rm -it alpine:latest sh
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/ # uname -a
Linux 5af89d05295b 5.0.0-37-generic #40~18.04.1-Ubuntu SMP Thu Nov 14 12:06:39 UTC 2019 x86_64 Linux
/ # cat /etc/passwd
root:x:0:0:root:/root:/bin/ash
...
/ # curl https://example.com/
...

$ cat log.json
{"data":{"container_id":"5af89d052","event":{"name":"execve","data":{"argv":"","comm":"","pid":"12555","ret":"0","uid":"0","user":"root"}}},"level":"info","msg":"execve","time":"2019-12-24T12:45:36Z"}
{"data":{"container_id":"5af89d052","event":{"name":"execve","data":{"argv":"","comm":"/usr/bin/id","pid":"12605","ret":"0","uid":"0","user":"root"}}},"level":"info","msg":"execve","time":"2019-12-24T12:45:37Z"}
{"data":{"container_id":"5af89d052","event":{"name":"execve","data":{"argv":"-a","comm":"/bin/uname","pid":"12608","ret":"0","uid":"0","user":"root"}}},"level":"info","msg":"execve","time":"2019-12-24T12:45:39Z"}
{"data":{"container_id":"5af89d052","event":{"name":"execve","data":{"argv":"/etc/passwd","comm":"/bin/cat","pid":"12609","ret":"0","uid":"0","user":"root"}}},"level":"info","msg":"execve","time":"2019-12-24T12:45:41Z"}
{"data":{"container_id":"5af89d052","event":{"name":"open","data":{"comm":"cat","fname":"/etc/passwd","pid":"14134","ret":"3","uid":"0"}}},"level":"info","msg":"open","time":"2019-12-25T02:02:27Z"}
{"data":{"container_id":"5af89d052","event":{"name":"tcp_v4_connect","data":{"comm":"curl","daddr":"93.184.216.34","dport":"443","pid":"17408","ret":"0","saddr":"172.17.0.2","uid":"0"}}},"level":"info","msg":"tcp_v4_connect","time":"2019-12-25T16:12:01Z"}
```

## Executing Processes (execve)

```json
{
  "data": {
    "container_id": "b85bd4425",
    "event": {
      "name": "execve",
      "data": {
        "argv": "-a",
        "comm": "/bin/uname",
        "pid": "1714",
        "ret": "0",
        "uid": "0",
        "user": "root"
      }
    }
  },
  "level": "info",
  "msg": "execve",
  "time": "2020-01-04T15:40:12Z"
}
```

## Opening File and Binaries (open)

```json
{
  "data": {
    "container_id": "b85bd4425",
    "event": {
      "name": "open",
      "data": {
        "comm": "cat",
        "fname": "/etc/shadow",
        "pid": "1715",
        "ret": "3",
        "uid": "0"
      }
    }
  },
  "level": "info",
  "msg": "open",
  "time": "2020-01-04T15:41:20Z"
}
```

## HTTP Connection (tcp_v4_connect)

```json
{
  "data": {
    "container_id": "b85bd4425",
    "event": {
      "name": "tcp_v4_connect",
      "data": {
        "comm": "wget",
        "daddr": "93.184.216.34",
        "dport": "443",
        "pid": "1716",
        "ret": "0",
        "saddr": "172.17.0.2",
        "uid": "0"
      }
    }
  },
  "level": "info",
  "msg": "tcp_v4_connect",
  "time": "2020-01-04T15:42:04Z"
}
```

## Network Listeners (inet_listen)

```json
{
  "data": {
    "container_id": "",
    "event": {
      "name": "inet_listen",
      "data": {
        "comm": "nc",
        "listen_addr": "0.0.0.0",
        "listen_port": "12345",
        "pid": "1723",
        "protocol": "tcp",
        "uid": "0"
      }
    }
  },
  "level": "info",
  "msg": "inet_listen",
  "time": "2020-01-04T15:42:43Z"
}
```

# Support Events

 * [x] Process Execution
 * [x] Access to files and binaries
 * [x] Creation of network listeners
 * [x] Traffic sent to network destinations
