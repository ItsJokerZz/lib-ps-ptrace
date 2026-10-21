# lib-ps-ptrace
A ptrace library for John Törnblom's PS4/5 Payload SDKs.

It wraps `ptrace(2)` for the PS4 and PS5 and adds what a payload needs to work on another process: attaching, reading and writing its memory, running syscalls and functions inside it, and resolving its symbols. One header, one static library per console.

| Console | SDK | Archive |
| --- | --- | --- |
| PS4 | [ps4-payload-sdk](https://github.com/ps4-payload-dev/sdk) | `build/ps4/libptrace.a` |
| PS5 | [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) | `build/ps5/libptrace.a` |

## Building
Point the matching variable at an installed SDK and run `make`.

```sh
export PS4_PAYLOAD_SDK=/opt/ps4-payload-sdk
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk

make                # every console whose SDK variable is set
make ps4            # PS4 only
make ps5            # PS5 only
make clean
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `PLATFORM` | unset | `ps4` or `ps5`; builds that console directly |
| `BUILD` | `build/<platform>` | Object and archive directory |
| `OPT` | `-O2` | Optimisation flags, for example `OPT=-Oz` |
| `DEBUG` | unset | Add `-g` when set |

## Installing
`install` follows the SDKs' package layout, so `DESTDIR` and `PREFIX` default to the SDK sysroot and `/user/homebrew`.

```sh
make install            # every console whose SDK variable is set
make install-ps5
make install-ps4 DESTDIR=/path/to/stage
```

This installs `include/ptrace.h`, `lib/libptrace.a` and `lib/pkgconfig/ptrace.pc` under `$(DESTDIR)$(PREFIX)`. Use the SDK's pkg-config to find them:

```make
CFLAGS += $(shell $(PKG_CONFIG) --cflags ptrace)
LDLIBS += $(shell $(PKG_CONFIG) --libs ptrace)
```

To put them next to the SDK's own headers and libraries instead, so the compiler finds them without flags, install with an empty prefix and link with `-lptrace -lkernel_sys`:

```sh
make install PREFIX=
```

## Using
```c
#include <ptrace.h>

int read_u64(pid_t pid, intptr_t address, uint64_t *value) {
  if (pt_attach(pid))
    return -1;

  int result = pt_copyout(pid, address, value, sizeof(*value));

  pt_detach(pid, 0);

  return result;
}
```

Functions return `0` on success and `-1` with `errno` set unless noted. The target has to be attached, and therefore stopped, before the calls that touch its registers or memory; `pt_read_memory` and `pt_write_memory` attach for you.

The same functions exist on both consoles with the same signatures. Where the two kernels need different tricks, the library picks them.

## Logging
Diagnostics go to stdout and klog, the same way elfldr logs.

## API
| Function | Purpose |
| --- | --- |
| `pt_attach`, `pt_detach` | Attach and wait for the stop (about five seconds at most), or detach and resume |
| `pt_step`, `pt_continue` | Single-step or resume the stopped process |
| `pt_breakat` | Resume the stopped process until it reaches an address, then put the original byte back and leave it stopped there |
| `pt_getregs`, `pt_setregs` | Read or write the registers of the stopped thread |
| `pt_copyin`, `pt_copyout` | Write to or read from the target's memory |
| `pt_read_memory`, `pt_write_memory` | The same, attaching and detaching around the copy |
| `pt_getchar`, `pt_getshort`, `pt_getint`, `pt_getlong`, `pt_setchar`, `pt_setshort`, `pt_setint`, `pt_setlong` | Typed memory access |
| `pt_syscall` | Run a syscall inside the target and return its result |
| `pt_mmap`, `pt_mprotect`, `pt_msync`, `pt_munmap` | Memory syscalls inside the target |
| `pt_close`, `pt_dup2`, `pt_rdup` | File descriptor syscalls inside the target |
| `pt_socket`, `pt_setsockopt`, `pt_bind`, `pt_recvmsg` | Socket syscalls inside the target |
| `pt_dynlib_get_proc_param`, `pt_dynlib_process_needed_and_relocate` | Console dynamic linker syscalls inside the target |
| `pt_resolve` | Find an exported function of the target's libkernel by name or by NID; returns `0` when it is not found |
| `pt_call` | Call a function on the stopped thread with up to six integer arguments and fetch `rax` |
| `pt_pipe`, `pt_errno`, `pt_sceKernelGetProcParam` | Helpers that call into the target's libkernel |

```c
intptr_t function = pt_resolve(pid, "getpid");
const uint64_t args[6] = {0};
intptr_t result;

if (function && !pt_call(pid, function, args, &result))
  printf("target pid is %ld\n", (long)result);
```

## Notes
- Both consoles need a payload that is allowed to use `ptrace`. On the PS5 the library raises the caller's authority id around each request and puts it back afterwards; requests are serialised with a lock so threads do not undo each other's change.
- `pt_call` runs the function on a stack of its own choosing, restores the thread's registers afterwards, and waits about ten seconds before it stops the process and gives up. On the PS4 it maps and frees its own scratch region; if a call times out that region is left behind because the function may still be running on it.
- `pt_resolve` takes a symbol name or an eleven-character NID on both consoles, so code written against upstream's NID-based `pt_resolve` works unchanged. A string that looks like an NID is tried as one first and then as a name; on the PS5 a name is turned into its NID before the lookup.
- `pt_breakat` plants a breakpoint at the address, resumes the process and waits about thirty seconds for it to stop. It returns `-1` with `ESRCH` if the process ended instead, or `ETIMEDOUT` if it never got there; the original byte is put back in both cases. On the PS5 the page has to be made writable through the kernel first, on the PS4 a ptrace write goes through as it is.
- A call that fails halfway restores the thread's registers where it can. Check the return value, and detach either way.

## Credits
Based on John Törnblom's `pt_*` ptrace helpers; his copyright notice is kept in every source file. The PS4 backend borrows the 832-byte FPU register layout from ps4debug-NG and the return-address check for remote calls from NexusFramework.

## License
GPL-3.0-or-later. See [LICENSE](LICENSE).
