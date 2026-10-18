/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifdef __ORBIS__
#include <ps4/kernel.h>
#endif

#ifdef __PROSPERO__
#include <pthread.h>

#include <ps5/kernel.h>
#include <ps5/nid.h>
#endif

#include "log.h"
#include "ptrace.h"

#ifdef __ORBIS__

#define PT_DETACH_ADDR ((caddr_t)1)
#define PT_STEP_STOPPED(status)                                               \
  (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
#define PT_SCRATCH_SIZE 0x20000

static int
sys_ptrace(int request, pid_t pid, caddr_t addr, int data) {
  return ptrace(request, pid, addr, data);
}

#endif

#ifdef __PROSPERO__

#define PT_DETACH_ADDR ((caddr_t)0)
#define PT_STEP_STOPPED(status) 1

static pthread_mutex_t sys_ptrace_lock = PTHREAD_MUTEX_INITIALIZER;

static int
sys_ptrace(int request, pid_t pid, caddr_t addr, int data) {
  pid_t mypid = getpid();
  uint64_t authid;
  int ret = -1;

  pthread_mutex_lock(&sys_ptrace_lock);

  if((authid = kernel_get_ucred_authid(mypid))
     && !kernel_set_ucred_authid(mypid, 0x4800000000010003l)) {
    ret = (int)syscall(SYS_ptrace, request, pid, addr, data);

    int error = errno;

    if(kernel_set_ucred_authid(mypid, authid)) {
      ret = -1;
    } else {
      errno = error;
    }
  }

  pthread_mutex_unlock(&sys_ptrace_lock);

  return ret;
}

#endif

static pid_t
pt_wait(pid_t pid, int *status, int options) {
  pid_t waited;

  do {
    waited = waitpid(pid, status, options);
  } while(waited < 0 && errno == EINTR && !(options & WNOHANG));

  return waited;
}

int
pt_attach(pid_t pid) {
  if(sys_ptrace(PT_ATTACH, pid, 0, 0) == -1) {
    return -1;
  }

  for(int poll = 0; poll < 500; ++poll) {
    int status = 0;
    pid_t waited = pt_wait(pid, &status, WNOHANG);

    if(waited == pid && WIFSTOPPED(status)) {
      return 0;
    }
    if(!waited || (waited < 0 && errno == EINTR)) {
      usleep(10000);
      continue;
    }

    int error = waited < 0 ? errno : ESRCH;

    pt_detach(pid, 0);
    errno = error;

    return -1;
  }

  int detached = pt_detach(pid, 0);

  LOG_PRINTF("[Ptrace] Attach timeout: pid=%d detach=%d errno=%d\n", pid,
             detached, detached ? errno : 0);
  errno = ETIMEDOUT;

  return -1;
}

int
pt_detach(pid_t pid, int sig) {
  if(sys_ptrace(PT_DETACH, pid, PT_DETACH_ADDR, sig) != -1) {
    return 0;
  }

  int error = errno;

  for(int poll = 0; poll < 20; ++poll) {
    int status = 0;
    pid_t waited = pt_wait(pid, &status, WNOHANG);

    if(waited == pid && WIFSTOPPED(status)
       && sys_ptrace(PT_DETACH, pid, PT_DETACH_ADDR, sig) != -1) {
      return 0;
    }
    if(waited) {
      break;
    }

    usleep(10000);
  }

  errno = error;

  return -1;
}

int
pt_step(pid_t pid) {
  if(sys_ptrace(PT_STEP, pid, (caddr_t)1, 0)) {
    return -1;
  }

  int status = 0;

  if(pt_wait(pid, &status, 0) != pid || !PT_STEP_STOPPED(status)) {
    return -1;
  }

  return 0;
}

int
pt_continue(pid_t pid, int sig) {
  if(sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, sig) == -1) {
    return -1;
  }

  return 0;
}

int
pt_getregs(pid_t pid, struct reg *r) {
  return sys_ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}

int
pt_setregs(pid_t pid, const struct reg *r) {
  return sys_ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}

static int
pt_io(pid_t pid, int op, intptr_t addr, void *buf, size_t len) {
  struct ptrace_io_desc iod = {
    .piod_op = op, .piod_offs = (void *)addr, .piod_addr = buf, .piod_len = len
  };

  if(sys_ptrace(PT_IO, pid, (caddr_t)&iod, 0) == -1) {
    return -1;
  }
  if(iod.piod_len != len) {
    errno = EIO;
    return -1;
  }

  return 0;
}

int
pt_copyin(pid_t pid, const void *buf, intptr_t addr, size_t len) {
  return pt_io(pid, PIOD_WRITE_D, addr, (void *)buf, len);
}

int
pt_copyout(pid_t pid, intptr_t addr, void *buf, size_t len) {
  return pt_io(pid, PIOD_READ_D, addr, buf, len);
}

static int
pt_session(pid_t pid, int op, intptr_t addr, void *buf, size_t len) {
  if(pt_attach(pid)) {
    return -1;
  }

  int result = pt_io(pid, op, addr, buf, len);
  int error = errno;

  if(pt_detach(pid, 0)) {
    return -1;
  }

  errno = error;

  return result;
}

int
pt_read_memory(pid_t pid, intptr_t addr, void *buf, size_t len) {
  return pt_session(pid, PIOD_READ_D, addr, buf, len);
}

int
pt_write_memory(pid_t pid, const void *buf, intptr_t addr, size_t len) {
  return pt_session(pid, PIOD_WRITE_D, addr, (void *)buf, len);
}

int
pt_getint(pid_t pid, intptr_t addr) {
  return sys_ptrace(PT_READ_D, pid, (caddr_t)addr, 0);
}

int
pt_setint(pid_t pid, intptr_t addr, int val) {
  return sys_ptrace(PT_WRITE_D, pid, (caddr_t)addr, val);
}

int
pt_setchar(pid_t pid, intptr_t addr, char val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}

int
pt_setshort(pid_t pid, intptr_t addr, short val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}

int
pt_setlong(pid_t pid, intptr_t addr, long val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}

char
pt_getchar(pid_t pid, intptr_t addr) {
  char val = 0;

  pt_copyout(pid, addr, &val, sizeof(val));

  return val;
}

short
pt_getshort(pid_t pid, intptr_t addr) {
  short val = 0;

  pt_copyout(pid, addr, &val, sizeof(val));

  return val;
}

long
pt_getlong(pid_t pid, intptr_t addr) {
  long val = 0;

  pt_copyout(pid, addr, &val, sizeof(val));

  return val;
}

static long
pt_syscall3(pid_t pid, int sysno, uint64_t a1, uint64_t a2, uint64_t a3) {
  return pt_syscall(pid, sysno, a1, a2, a3, 0ULL, 0ULL, 0ULL);
}

intptr_t
pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags, int fd,
        off_t off) {
  return pt_syscall(pid, SYS_mmap, (uint64_t)addr, (uint64_t)len,
                    (uint64_t)prot, (uint64_t)flags, (uint64_t)(int64_t)fd,
                    (uint64_t)off);
}

int
pt_mprotect(pid_t pid, intptr_t addr, size_t len, int prot) {
  return (int)pt_syscall3(pid, SYS_mprotect, addr, len, (uint64_t)prot);
}

int
pt_msync(pid_t pid, intptr_t addr, size_t len, int flags) {
  return (int)pt_syscall3(pid, SYS_msync, addr, len, (uint64_t)flags);
}

int
pt_munmap(pid_t pid, intptr_t addr, size_t len) {
  return (int)pt_syscall3(pid, SYS_munmap, addr, len, 0);
}

int
pt_close(pid_t pid, int fd) {
  return (int)pt_syscall3(pid, SYS_close, (uint64_t)fd, 0, 0);
}

int
pt_dup2(pid_t pid, int oldfd, int newfd) {
  return (int)pt_syscall3(pid, SYS_dup2, (uint64_t)oldfd, (uint64_t)newfd, 0);
}

int
pt_rdup(pid_t pid, pid_t other_pid, int fd) {
  return (int)pt_syscall3(pid, 0x25b, (uint64_t)other_pid, (uint64_t)fd, 0);
}

int
pt_socket(pid_t pid, int domain, int type, int protocol) {
  return (int)pt_syscall3(pid, SYS_socket, (uint64_t)domain, (uint64_t)type,
                          (uint64_t)protocol);
}

int
pt_setsockopt(pid_t pid, int fd, int level, int optname, intptr_t optval,
              uint32_t optlen) {
  return (int)pt_syscall(pid, SYS_setsockopt, (uint64_t)fd, (uint64_t)level,
                         (uint64_t)optname, (uint64_t)optval, (uint64_t)optlen,
                         0ULL);
}

int
pt_bind(pid_t pid, int sockfd, intptr_t addr, uint32_t addrlen) {
  return (int)pt_syscall3(pid, SYS_bind, (uint64_t)sockfd, (uint64_t)addr,
                          (uint64_t)addrlen);
}

ssize_t
pt_recvmsg(pid_t pid, int fd, intptr_t msg, int flags) {
  return (ssize_t)pt_syscall3(pid, SYS_recvmsg, (uint64_t)fd, (uint64_t)msg,
                              (uint64_t)flags);
}

int
pt_dynlib_get_proc_param(pid_t pid, intptr_t param_ptr, intptr_t size_ptr) {
  return (int)pt_syscall3(pid, 0x256, param_ptr, size_ptr, 0);
}

int
pt_dynlib_process_needed_and_relocate(pid_t pid) {
  return (int)pt_syscall3(pid, 0x257, 0, 0, 0);
}

static intptr_t
pt_dlsym(pid_t pid, const char *symbol) {
  static const char *const modules[]
      = { "libkernel.sprx", "libkernel_sys.sprx", "libkernel_web.sprx",
          "libSceLibcInternal.sprx" };

  for(size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); ++i) {
    uint32_t handle;

    if(kernel_dynlib_handle(pid, modules[i], &handle)) {
      continue;
    }

    intptr_t address = kernel_dynlib_dlsym(pid, handle, symbol);

    if(address > 0) {
      return address;
    }
  }

  return 0;
}

#ifdef __ORBIS__

struct ps4_fpregs {
  unsigned char legacy[512];
  unsigned char xstate_header[64];
  unsigned char ymm_upper[256];
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct ps4_fpregs) == 832, "PS4 FPU register ABI");

static intptr_t
pt_syscall_address(pid_t pid, unsigned number) {
  unsigned handle = 0;
  dynlib_obj_t module;
  uint8_t expected[12]
      = { 0x48, 0xc7, 0xc0, 0, 0, 0, 0, 0x49, 0x89, 0xca, 0x0f, 0x05 };
  uint8_t block[4096];

  if((kernel_dynlib_handle(pid, "libkernel_sys.sprx", &handle)
      && kernel_dynlib_handle(pid, "libkernel.sprx", &handle)
      && kernel_dynlib_handle(pid, "libkernel_web.sprx", &handle))
     || kernel_dynlib_obj(pid, handle, &module)) {
    return 0;
  }
  if(!module.textsize || module.textsize > 16 * 1024 * 1024) {
    errno = ENOEXEC;
    return 0;
  }

  memcpy(expected + 3, &number, sizeof(number));

  for(size_t off = 0; off < module.textsize;
      off += sizeof(block) - sizeof(expected)) {
    size_t length = module.textsize - off;

    if(length > sizeof(block)) {
      length = sizeof(block);
    }
    if(pt_copyout(pid, module.mapbase + off, block, length)) {
      return 0;
    }

    for(size_t i = 0; i + sizeof(expected) <= length; ++i) {
      if(!memcmp(block + i, expected, sizeof(expected))) {
        return module.mapbase + off + i + 10;
      }
    }
  }

  errno = ENOSYS;

  return 0;
}

long
pt_syscall(pid_t pid, int sysno, ...) {
  struct ptrace_lwpinfo origin = { 0 };
  struct reg sysc_reg;
  struct reg bak_reg;
  va_list ap;

  if(ptrace(PT_LWPINFO, pid, (caddr_t)&origin, sizeof(origin))
     || origin.pl_lwpid <= 0) {
    return -1;
  }

  pid_t tid = origin.pl_lwpid;
  intptr_t syscall_ip = pt_syscall_address(pid, sysno);

  if(!syscall_ip) {
    LOG_PERROR("resolve syscall stub");
    return -1;
  }

  if(pt_getregs(tid, &bak_reg)) {
    LOG_PERROR("syscall: PT_GETREGS before execution");
    return -1;
  }

  memcpy(&sysc_reg, &bak_reg, sizeof(sysc_reg));
  sysc_reg.r_rax = sysno;
  sysc_reg.r_rip = syscall_ip;

  va_start(ap, sysno);
  sysc_reg.r_rdi = va_arg(ap, uint64_t);
  sysc_reg.r_rsi = va_arg(ap, uint64_t);
  sysc_reg.r_rdx = va_arg(ap, uint64_t);
  sysc_reg.r_r10 = va_arg(ap, uint64_t);
  sysc_reg.r_r8 = va_arg(ap, uint64_t);
  sysc_reg.r_r9 = va_arg(ap, uint64_t);
  va_end(ap);

  if(pt_setregs(tid, &sysc_reg)) {
    LOG_PERROR("syscall: PT_SETREGS before execution");
    return -1;
  }

  int failed = -1;

  for(int attempt = 0; attempt < 16; ++attempt) {
    if(ptrace(PT_STEP, tid, (caddr_t)1, 0)) {
      break;
    }

    int status = 0;

    if(pt_wait(pid, &status, 0) != pid || !WIFSTOPPED(status)) {
      errno = EPROTO;
      break;
    }

    struct ptrace_lwpinfo event = { 0 };

    if(ptrace(PT_LWPINFO, pid, (caddr_t)&event, sizeof(event))
       || pt_getregs(tid, &sysc_reg)) {
      break;
    }

    int sig = WSTOPSIG(status);

    if((sig == SIGTRAP || sig == SIGSTOP)
       && (uint64_t)sysc_reg.r_rip == (uint64_t)syscall_ip + 2) {
      failed = 0;
      break;
    }

    LOG_PRINTF("[Ptrace] syscall=%d stop=%#x event LWP=%d original=%d "
               "RIP=%#lx expected=%#lx\n",
               sysno, status, (int)event.pl_lwpid, (int)tid,
               (unsigned long)sysc_reg.r_rip,
               (unsigned long)((uint64_t)syscall_ip + 2));

    if(sig != SIGSTOP || (uint64_t)sysc_reg.r_rip != (uint64_t)syscall_ip) {
      errno = EPROTO;
      break;
    }

    errno = EAGAIN;
  }

  if(failed) {
    LOG_PERROR("syscall: PT_STEP/wait");
  } else {
    failed = pt_getregs(tid, &sysc_reg);

    if(failed) {
      LOG_PERROR("syscall: PT_GETREGS after execution");
    }
  }

  int saved_error = failed ? errno : 0;

  if(pt_setregs(tid, &bak_reg)) {

    int restore_error = errno;
    struct reg now;
    int restored = 0;

    if(!pt_getregs(tid, &now)) {
      const uint64_t user_flags = 0x254dd5;
      struct reg merged = bak_reg;

      LOG_PRINTF("[Ptrace] Restore refused (errno=%d): saved rflags=%#lx "
                 "cs=%#lx ss=%#lx, now rflags=%#lx cs=%#lx ss=%#lx\n",
                 restore_error, (unsigned long)bak_reg.r_rflags,
                 (unsigned long)bak_reg.r_cs, (unsigned long)bak_reg.r_ss,
                 (unsigned long)now.r_rflags, (unsigned long)now.r_cs,
                 (unsigned long)now.r_ss);

      merged.r_rflags
          = (bak_reg.r_rflags & user_flags) | (now.r_rflags & ~user_flags);
      merged.r_cs = now.r_cs;
      merged.r_ss = now.r_ss;
      restored = !pt_setregs(tid, &merged);

      LOG_PRINTF("[Ptrace] Restore with the thread's own protected bits %s\n",
                 restored ? "succeeded" : "was refused as well");
    }
    if(!restored) {
      errno = restore_error;
      LOG_PERROR("syscall: restore registers");

      if(!saved_error) {
        saved_error = errno;
      }
      failed = -1;
    }
  }
  if(failed) {
    errno = saved_error;
    return -1;
  }
  if(sysc_reg.r_rflags & 1) {
    errno = (int)sysc_reg.r_rax;
    LOG_PRINTF("[Ptrace] Remote syscall %d at %#lx returned errno=%d (%s)\n",
               sysno, (unsigned long)bak_reg.r_rip, errno, strerror(errno));
    return -1;
  }

  return sysc_reg.r_rax;
}

static int
pt_call_on(pid_t pid, intptr_t function, intptr_t scratch, size_t scratch_size,
           const uint64_t args[6], intptr_t *result, int *retain) {
  struct ptrace_lwpinfo origin = { 0 };
  struct ps4_fpregs fp = { 0 };
  struct reg saved, call;
  uint8_t trap = 0xcc;
  int failed = 1, stopped = 1;

  if(ptrace(PT_LWPINFO, pid, (caddr_t)&origin, sizeof(origin))
     || origin.pl_lwpid <= 0) {
    LOG_PERROR("call: cannot identify stopped LWP");
    return -1;
  }

  pid_t tid = origin.pl_lwpid;

  if(pt_getregs(tid, &saved) || ptrace(PT_GETFPREGS, tid, (caddr_t)&fp, 0)) {
    LOG_PERROR("call: save LWP registers");
    return -1;
  }

  LOG_PRINTF("[Ptrace] Remote call LWP=%d function=%#lx saved RIP=%#lx\n",
             (int)tid, (unsigned long)function, (unsigned long)saved.r_rip);

  call = saved;

  intptr_t stack = ((scratch + scratch_size) & ~(intptr_t)15) - 8;

  if(pt_copyin(pid, &trap, scratch, 1)
     || pt_copyin(pid, &scratch, stack, sizeof(scratch))) {
    return -1;
  }

  call.r_rip = function;
  call.r_rsp = stack;
  call.r_rdi = args[0];
  call.r_rsi = args[1];
  call.r_rdx = args[2];
  call.r_rcx = args[3];
  call.r_r8 = args[4];
  call.r_r9 = args[5];
  call.r_rax = 0;
  call.r_rflags &= ~0x100ULL;

  if(pt_setregs(tid, &call)) {
    return -1;
  }
  if(pt_continue(pid, 0)) {
    goto restore;
  }

  stopped = 0;

  for(int i = 0; i < 1000; ++i) {
    int status = 0;
    pid_t waited = waitpid(pid, &status, WNOHANG);

    if(!waited || (waited < 0 && errno == EINTR)) {
      usleep(10000);
      continue;
    }
    if(waited != pid || !WIFSTOPPED(status)) {
      break;
    }

    stopped = 1;

    struct ptrace_lwpinfo event = { 0 };

    if(ptrace(PT_LWPINFO, pid, (caddr_t)&event, sizeof(event))) {
      break;
    }

    LOG_PRINTF("[Ptrace] Remote stop=%#x LWP=%d expected=%d\n", status,
               (int)event.pl_lwpid, (int)tid);

    if(pt_getregs(tid, &call)) {
      break;
    }

    if((uint64_t)call.r_rip == (uint64_t)scratch + 1) {
      *result = call.r_rax;
      failed = 0;
      break;
    }
    if(WSTOPSIG(status) == SIGSTOP) {

      if(pt_continue(pid, 0)) {
        break;
      }

      stopped = 0;
      continue;
    }

    LOG_PRINTF("[Ptrace] Call did not return: pid=%d signal=%d RIP=%#lx "
               "RSP=%#lx return=%#lx\n",
               pid, WSTOPSIG(status), (unsigned long)call.r_rip,
               (unsigned long)call.r_rsp, (unsigned long)(scratch + 1));
    break;
  }

  if(!stopped) {
    LOG_PUTS("[Ptrace] Remote call incomplete; requesting stop before LWP "
             "restoration");
    kill(pid, SIGSTOP);

    for(int i = 0; i < 200; ++i) {
      int status = 0;
      pid_t waited = waitpid(pid, &status, WNOHANG);

      if(waited == pid) {
        stopped = WIFSTOPPED(status);
        break;
      }
      if(waited < 0 && errno != EINTR) {
        break;
      }

      usleep(10000);
    }
  }
  if(!stopped) {
    *retain = 1;
    errno = ETIMEDOUT;
    return -1;
  }

restore:
  LOG_PRINTF("[Ptrace] Restoring original LWP=%d; completed=%d\n", (int)tid,
             !failed);

  if(ptrace(PT_SETFPREGS, tid, (caddr_t)&fp, 0)) {
    LOG_PERROR("call: restore FP registers");
    failed = 1;
  }
  if(pt_setregs(tid, &saved)) {
    LOG_PERROR("call: restore registers");
    failed = 1;
  }

  return failed ? -1 : 0;
}

intptr_t
pt_resolve(pid_t pid, const char *symbol) {
  return pt_dlsym(pid, symbol);
}

int
pt_call(pid_t pid, intptr_t function, const uint64_t args[6],
        intptr_t *result) {
  const unsigned char zero = 0;
  int retain = 0;
  intptr_t scratch
      = pt_mmap(pid, 0, PT_SCRATCH_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if(scratch <= 0) {
    return -1;
  }

  for(size_t off = 0; off < PT_SCRATCH_SIZE; off += 0x1000) {
    if(pt_copyin(pid, &zero, scratch + off, 1)) {
      int error = errno;

      pt_munmap(pid, scratch, PT_SCRATCH_SIZE);
      errno = error;

      return -1;
    }
  }

  int status = pt_call_on(pid, function, scratch, PT_SCRATCH_SIZE, args,
                          result, &retain);

  if(!retain) {
    int error = errno;

    pt_munmap(pid, scratch, PT_SCRATCH_SIZE);
    errno = error;
  }

  return status;
}

int
pt_pipe(pid_t pid, intptr_t pipefd) {
  intptr_t function = pt_resolve(pid, "pipe");
  const uint64_t args[6] = { (uint64_t)pipefd };
  intptr_t result = -1;

  if(!function || pt_call(pid, function, args, &result)) {
    return -1;
  }

  return (int)result;
}

int
pt_errno(pid_t pid) {
  intptr_t function = pt_resolve(pid, "__error");
  const uint64_t args[6] = { 0 };
  intptr_t address = 0;

  if(!function || pt_call(pid, function, args, &address) || !address) {
    return -1;
  }

  return pt_getint(pid, address);
}

intptr_t
pt_sceKernelGetProcParam(pid_t pid) {
  intptr_t function = pt_resolve(pid, "sceKernelGetProcParam");
  const uint64_t args[6] = { 0 };
  intptr_t param = 0;

  if(!function || pt_call(pid, function, args, &param)) {
    return 0;
  }

  return param;
}

#endif

#ifdef __PROSPERO__

static intptr_t
resolve_nid(pid_t pid, const char *nid) {
  intptr_t addr;

  if((addr = kernel_dynlib_resolve(pid, 0x1, nid))) {
    return addr;
  }

  return kernel_dynlib_resolve(pid, 0x2001, nid);
}

intptr_t
pt_resolve(pid_t pid, const char *symbol) {
  char nid[12] = { 0 };
  intptr_t addr;

  nid_encode(symbol, nid);

  if((addr = resolve_nid(pid, nid))) {
    return addr;
  }

  return pt_dlsym(pid, symbol);
}

static void
pt_arguments(struct reg *r, int kernel_abi, va_list ap) {
  r->r_rdi = va_arg(ap, uint64_t);
  r->r_rsi = va_arg(ap, uint64_t);
  r->r_rdx = va_arg(ap, uint64_t);

  if(kernel_abi) {
    r->r_r10 = va_arg(ap, uint64_t);
  } else {
    r->r_rcx = va_arg(ap, uint64_t);
  }

  r->r_r8 = va_arg(ap, uint64_t);
  r->r_r9 = va_arg(ap, uint64_t);
}

static long
pt_run_stepped(pid_t pid, const struct reg *bak_reg, struct reg *jmp_reg) {
  if(pt_setregs(pid, jmp_reg)) {
    return -1;
  }

  while(jmp_reg->r_rsp <= bak_reg->r_rsp) {
    if(pt_step(pid) || pt_getregs(pid, jmp_reg)) {
      pt_setregs(pid, bak_reg);
      return -1;
    }
  }

  if(pt_setregs(pid, bak_reg)) {
    return -1;
  }

  return jmp_reg->r_rax;
}

long
pt_syscall(pid_t pid, int sysno, ...) {
  intptr_t addr = resolve_nid(pid, "HoLVWNanBBc");
  struct reg jmp_reg;
  struct reg bak_reg;
  va_list ap;

  if(!addr) {
    return -1;
  }
  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr + 0xa;
  jmp_reg.r_rax = sysno;

  va_start(ap, sysno);
  pt_arguments(&jmp_reg, 1, ap);
  va_end(ap);

  return pt_run_stepped(pid, &bak_reg, &jmp_reg);
}

static long
pt_call_single_step(pid_t pid, intptr_t addr, ...) {
  struct reg jmp_reg;
  struct reg bak_reg;
  va_list ap;

  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;

  va_start(ap, addr);
  pt_arguments(&jmp_reg, 0, ap);
  va_end(ap);

  return pt_run_stepped(pid, &bak_reg, &jmp_reg);
}

static int
pt_wait_stopped(pid_t pid, unsigned timeout_ms) {
  for(unsigned waited = 0; waited < timeout_ms; waited += 10) {
    int status = 0;
    pid_t result = pt_wait(pid, &status, WNOHANG);

    if(result == pid) {
      return WIFSTOPPED(status) ? 1 : -1;
    }
    if(result < 0 && errno != EINTR) {
      return -1;
    }

    usleep(10000);
  }

  return 0;
}

int
pt_call(pid_t pid, intptr_t function, const uint64_t args[6],
        intptr_t *result) {
  struct reg bak, cur;
  intptr_t tramp = 0;
  uint8_t int3 = 0xCC;
  int stopped, error;

  if(pt_getregs(pid, &bak)) {
    return -1;
  }

  tramp = pt_mmap(pid, 0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if(tramp <= 0) {
    goto fail;
  }
  if(pt_copyin(pid, &int3, tramp, 1)) {
    goto fail;
  }

  cur = bak;
  cur.r_rip = function;

  cur.r_rdi = args[0];
  cur.r_rsi = args[1];
  cur.r_rdx = args[2];
  cur.r_rcx = args[3];
  cur.r_r8 = args[4];
  cur.r_r9 = args[5];

  cur.r_rsp = ((bak.r_rsp - 128) & ~(register_t)15) - 8;

  if(pt_copyin(pid, &tramp, cur.r_rsp, sizeof(tramp))) {
    goto fail;
  }
  if(pt_setregs(pid, &cur)) {
    goto fail;
  }
  if(pt_continue(pid, SIGCONT)) {
    goto fail;
  }

  stopped = pt_wait_stopped(pid, 10000);

  if(!stopped) {
    LOG_PUTS("[Ptrace] Remote call incomplete; requesting stop before "
             "restoring the registers");
    kill(pid, SIGSTOP);

    if(!pt_wait_stopped(pid, 2000)) {
      errno = ETIMEDOUT;
      return -1;
    }

    errno = ETIMEDOUT;
    goto fail;
  }
  if(stopped < 0 || pt_getregs(pid, &cur)) {
    goto fail;
  }

  if(result) {
    *result = cur.r_rax;
  }

  pt_setregs(pid, &bak);
  pt_munmap(pid, tramp, 0x1000);

  return 0;

fail:
  error = errno;

  if(tramp > 0) {
    pt_munmap(pid, tramp, 0x1000);
  }

  pt_setregs(pid, &bak);
  errno = error;

  return -1;
}

int
pt_pipe(pid_t pid, intptr_t pipefd) {
  intptr_t faddr = resolve_nid(pid, "-Jp7F+pXxNg");

  return (int)pt_call_single_step(pid, faddr, pipefd);
}

int
pt_errno(pid_t pid) {
  intptr_t faddr = resolve_nid(pid, "9BcDykPmo1I");
  intptr_t addr = pt_call_single_step(pid, faddr);

  return pt_getint(pid, addr);
}

intptr_t
pt_sceKernelGetProcParam(pid_t pid) {
  intptr_t faddr = resolve_nid(pid, "959qrazPIrg");
  intptr_t param = pt_call_single_step(pid, faddr);

  return param == -1 ? 0 : param;
}

#endif
