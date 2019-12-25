# cxray

cxray is a tool for integrating with other security tools by whitelisting events in containers.  
cxrat can profile events in the container by tracing processes and open files in a container.

# Background

Container security tools should be able to automatically profile containerized apps using behavioral learning and build.  
According to [NIST.SP.800-19](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf), must get the following events:

 * Invalid or unexpected process execution,
 * Invalid or unexpected system calls,
 * Changes to protected configuration files and binaries,
 * Writes to unexpected locations and file types,
 * Creation of unexpected network listeners,
 * Traffic sent to unexpected network destinations, and
 * Malware storage or execution.

cxray was created to profile these events.  
You can whitelist container events by running cxray in a development or test environment.


# Usage

```shell
$ sudo ./cxray > execve.json

$ docker run --rm -it alpine:latest sh
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/ # uname -a
Linux 5af89d05295b 5.0.0-37-generic #40~18.04.1-Ubuntu SMP Thu Nov 14 12:06:39 UTC 2019 x86_64 Linux
/ # cat /etc/passwd
root:x:0:0:root:/root:/bin/ash
...

$ cat execve.json
{"data":{"container_id":"5af89","event":{"syscall":"execve","data":{"argv":"","comm":"","pid":"12555","ret":"0","uid":"0","user":"root"}}},"level":"info","msg":"execve","time":"2019-12-24T12:45:36Z"}
{"data":{"container_id":"5af89","event":{"syscall":"execve","data":{"argv":"","comm":"/usr/bin/id","pid":"12605","ret":"0","uid":"0","user":"root"}}},"level":"info","msg":"execve","time":"2019-12-24T12:45:37Z"}
{"data":{"container_id":"5af89","event":{"syscall":"execve","data":{"argv":"-a","comm":"/bin/uname","pid":"12608","ret":"0","uid":"0","user":"root"}}},"level":"info","msg":"execve","time":"2019-12-24T12:45:39Z"}
{"data":{"container_id":"5af89","event":{"syscall":"execve","data":{"argv":"/etc/passwd","comm":"/bin/cat","pid":"12609","ret":"0","uid":"0","user":"root"}}},"level":"info","msg":"execve","time":"2019-12-24T12:45:41Z"}
{"data":{"container_id":"5af89d052","event":{"syscall":"open","data":{"comm":"cat","fname":"/etc/passwd","pid":"14134","ret":"3","uid":"0"}}},"level":"info","msg":"open","time":"2019-12-25T02:02:27Z"}
```

# Support

 * [x] Invalid or unexpected process execution
 * [x] Invalid or unexpected system calls
 * [x] Changes to protected configuration files and binaries
 * [ ] Writes to unexpected locations and file types
 * [ ] Creation of unexpected network listeners
 * [ ] Traffic sent to unexpected network destinations
 * [ ] Malware storage or execution
