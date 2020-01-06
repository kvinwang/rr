#!/usr/bin/env python3

"""
Usage: rr dump -m | ./findfd.py

"""

import re
import codecs
import struct


CARING_CALLS = ["socket", "open", "open64", "openat", "pipe", "pipe2"]


def get_value(line, key):
    try:
        return re.findall(r'%s:([0-9xa-f]*)' % key, line)[0]
    except IndexError:
        return None


def callname(key):
    return "SYSCALL: %s'" % key


class PidMan:
    def __init__(self):
        self.pids = {}

    def add_root(self, pid):
        self.pids[int(pid)] = int(pid)

    def add_thread(self, pid, child):
        self.pids[int(child)] = self.pids[pid]

    def get_pid(self, tid):
        return self.pids.get(int(tid), 1000000+int(tid))


class FdFinder:
    def __init__(self, fileobj):
        self.fileobj = fileobj
        self.entering = {}
        self.live_fds = {}
        self.pidman = PidMan()

        _ = self.readline()
        line = self.readline()
        self.root = int(get_value(line, "tid"))
        self.pidman.add_root(self.root)

    def readline(self):
        return self.fileobj.readline()

    def process_entering(self, line):
        tid = int(get_value(line, "tid"))
        pid = self.pidman.get_pid(tid)
        if pid != self.root:
            return
        next_line = self.readline()
        time = int(get_value(line, "global_time"))

        if callname("dup2") in line:
            fd = int(get_value(next_line, 'rsi'), base=16)
            pid = self.pidman.get_pid(tid)
            self.live_fds[fd] = {
                "syscall": "dup2",
                "global_time": time,
                'enter': time - 1,
                'fd': fd,
                'tid': tid,
                'pid': pid
            }
            return

        if callname("close") in line:
            fd = int(get_value(next_line, 'rdi'), base=16)
            pid = self.pidman.get_pid(tid)
            if fd in self.live_fds and self.live_fds[fd]['pid'] == pid:
                del self.live_fds[fd]
            return

        for key in CARING_CALLS:
            if callname(key) in line:
                self.entering[tid] = {"syscall": key, "enter": time}
                return

    def process_exiting(self, line):
        tid = int(get_value(line, "tid"))
        pid = self.pidman.get_pid(tid)
        if pid != self.root:
            return

        next_line = self.readline()
        rax = int(get_value(next_line, "rax"), base=16)
        time = int(get_value(line, "global_time"))
        if callname('fork') in line:
            self.pidman.add_root(rax)
            return
        elif callname('clone') in line:
            flags = int(get_value(next_line, "rdi"), base=16)
            # 0x10100 = CLONE_VM & CLONE_THREAD
            if 0x10100 & flags:
                # thread
                self.pidman.add_thread(pid, rax)
            else:
                # process
                self.pidman.add_root(rax)
            return

        for key in CARING_CALLS:
            if callname(key) in line:
                if tid not in self.entering:
                    continue
                assert self.entering[tid]['syscall'] == key
                hex_data = ""
                if key in {"pipe", "pipe2"}:
                    mem = self.readline()
                    hex_data = get_value(mem, "data")
                    if not hex_data:
                        raise Exception("Please run 'rr dump' with '-m' option")
                    bin_data = codecs.decode(hex_data, "hex")
                    fds = struct.unpack("@ii", bin_data)
                else:
                    fds = [rax]
                for fd in fds:
                    if fd < 0 or fd > 0x8fffffff:
                        continue
                    if fd in self.live_fds:
                        print(f"override: {self.live_fds[fd]}")
                    time = self.entering[tid]['enter']
                    self.live_fds[fd] = {
                        "syscall": key,
                        "global_time": time,
                        'enter': time-1,
                        'hex': hex_data,
                        'fd': fd,
                        'tid': tid,
                        'pid': pid
                    }

    def find_all(self):
        while True:
            line = self.readline()
            if not line:
                break
            if "ENTERING_SYSCALL" in line:
                self.process_entering(line)
            elif "EXITING_SYSCALL" in line:
                self.process_exiting(line)
        return self.live_fds


def find_all(fileobj):
    finder = FdFinder(fileobj)
    return finder.find_all().values()


def main():
    import sys
    fds = find_all(sys.stdin)
    for i in (sorted(fds, key=lambda x: int(x['enter']))):
        print(i)


if __name__ == '__main__':
    main()


