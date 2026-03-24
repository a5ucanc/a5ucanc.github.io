---
title: "Exploiting a Heap Overflow in the Linux Kernel's io_uring Subsystem"
description: "A walkthrough of a heap overflow vulnerability in io_uring, from root-cause analysis to reliable LPE via cross-cache exploitation and kernel ROP."
pubDate: 2025-11-14
tags: ["kernel", "exploit-dev", "linux", "heap", "lpe", "rop"]
difficulty: "advanced"
---

## Introduction

`io_uring` has become one of the most interesting attack surfaces in the Linux kernel. Since its introduction in 5.1, it has accumulated a string of high-severity CVEs — many involving memory corruption in the submission queue processing path. This post walks through a heap overflow vulnerability caused by an integer overflow in allocation size computation, the exploitation strategy using `msg_msg` objects for a reliable primitive, and the ultimate privilege escalation path through `task_struct->cred`.

---

## Root Cause: Integer Overflow in Allocation Size

The vulnerability lives in the `io_uring` setup path when computing the size of an internal buffer. A simplified version of the vulnerable code:

```c
// VULNERABLE — kernel version <= 6.x.y
static int io_allocate_scq_urings(struct io_ring_ctx *ctx,
                                   struct io_uring_params *p)
{
    size_t size, sq_size, cq_size;

    sq_size = sizeof(struct io_uring_sqe) * p->sq_entries;  // (1)
    cq_size = sizeof(struct io_uring_cqe) * p->cq_entries;  // (2)

    size = sq_size + cq_size;                                 // (3) -- wraps!

    ctx->sq_sqes = kvmalloc(size, GFP_KERNEL);               // (4) -- undersized alloc
    if (!ctx->sq_sqes)
        return -ENOMEM;
    // ...copy user data into undersized buffer...
}
```

Steps (1) and (2) individually may not overflow, but the addition at (3) can wrap to a small value if an attacker passes crafted `sq_entries` and `cq_entries` values. `kvmalloc` then allocates a buffer far smaller than the data subsequently copied into it, yielding a classic heap overflow.

### The Fix: `check_mul_overflow`

The upstream patch replaces the bare multiplications with the kernel's checked arithmetic helpers:

```c
// PATCHED
static int io_allocate_scq_urings(struct io_ring_ctx *ctx,
                                   struct io_uring_params *p)
{
    size_t size, sq_size, cq_size;

    if (check_mul_overflow(sizeof(struct io_uring_sqe),
                           (size_t)p->sq_entries, &sq_size))
        return -EOVERFLOW;

    if (check_mul_overflow(sizeof(struct io_uring_cqe),
                           (size_t)p->cq_entries, &cq_size))
        return -EOVERFLOW;

    if (check_add_overflow(sq_size, cq_size, &size))
        return -EOVERFLOW;

    ctx->sq_sqes = kvmalloc(size, GFP_KERNEL);
    if (!ctx->sq_sqes)
        return -ENOMEM;
}
```

`check_mul_overflow` and `check_add_overflow` return `true` when overflow would occur, causing an early `-EOVERFLOW` return before the allocation.

---

## Heap Feng Shui with `msg_msg`

Raw heap overflow to controlled write is only the beginning. To build a useful exploitation primitive we need a well-known, controllable object adjacent to the overflow target. `msg_msg` objects (used by System V message queues) are a classic choice because:

- They are allocated from `kmalloc` slabs of arbitrary size (controlled by message body length).
- The first 48 bytes are the `msg_msg` header; everything after is attacker-controlled message body.
- Corrupting the `m_ts` (message body size) or the `next` pointer in the header yields an out-of-bounds read or a fake object read primitive.

### Grooming Strategy

1. **Drain the target slab** by allocating many objects of the same cache size as the io_uring buffer, then freeing alternating ones to create holes.
2. **Place `msg_msg` objects** into the holes so an io_uring buffer sits adjacent to a `msg_msg` header.
3. **Trigger the overflow**, overwriting the `msg_msg` header's `m_ts` field with a large value.
4. **Call `msgrcv`** with `MSG_COPY` to read up to `m_ts` bytes — this leaks kernel heap data beyond the message body, including pointers.

From the leaked pointers we can derive:
- A `kmalloc` heap address (breaks KASLR for the heap region).
- A kernel `.text` pointer if a function pointer happens to reside in an adjacent object (combined with a secondary info-leak, breaks KASLR for the text segment).

---

## Privilege Escalation via `task_struct->cred`

With KASLR defeated and a write primitive in hand, the standard LPE path targets `task_struct->cred`:

```c
// Conceptual -- real exploit uses ROP to call this in kernel context
void escalate(void)
{
    struct cred *new = prepare_kernel_cred(NULL);  // alloc cred with uid=0
    commit_creds(new);                              // swap current task's cred
}
```

Because we cannot call these functions directly from userland, we build a **kernel ROP chain** that:

1. Pivots the stack to a controlled buffer (using a `push rsp; ret` or `xchg rax, rsp; ret` gadget found via ropper/ROPgadget against the leaked kernel base).
2. Calls `prepare_kernel_cred(0)` to allocate a fresh privileged credential structure.
3. Passes the returned pointer to `commit_creds`.
4. Returns cleanly to userland via `swapgs; iretq` or the KPTI trampoline.

### SMEP/KPTI Bypass

With SMEP enabled the stack pivot cannot land in userspace memory. Use a kernel heap buffer (already mapped) as the ROP stack. KPTI is handled by using the `native_swapgs_restore_regs_and_return_to_usermode` trampoline rather than a bare `swapgs; iretq` sequence.

---

## Patch Analysis Summary

| Component | Before | After |
|---|---|---|
| `sq_size` computation | `sizeof(sqe) * p->sq_entries` | `check_mul_overflow(...)` |
| `cq_size` computation | `sizeof(cqe) * p->cq_entries` | `check_mul_overflow(...)` |
| `size` computation | `sq_size + cq_size` | `check_add_overflow(...)` |
| Error on overflow | None (silent wrap) | Returns `-EOVERFLOW` |

The fix is minimal and correct. The broader lesson is that any kernel path accepting user-controlled sizes must use the `check_*_overflow` family or equivalent saturation arithmetic before passing values to allocators.

---

## Conclusion

`io_uring`'s complexity and the tight coupling between user-controlled parameters and kernel memory allocation make it a recurring source of memory-safety bugs. The exploitation path described here — integer overflow to heap overflow to `msg_msg` feng shui to KASLR defeat to kernel ROP to `commit_creds` LPE — is representative of modern Linux kernel exploitation methodology. Defenders should prioritize kernel hardening options (`CONFIG_RANDOMIZE_KSTACK_OFFSET`, `CONFIG_INIT_ON_ALLOC_DEFAULT_ON`) and keep kernels patched promptly when io_uring CVEs are disclosed.
