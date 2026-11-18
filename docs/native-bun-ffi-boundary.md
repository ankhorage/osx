# Native Bun cache boundary decision

## Status

`@ankhorage/osx` keeps Bun package-cache cleanup report-only. No runtime adapter is enabled.

## Evidence

The macOS fixture in `tests/nativeBunFfiBoundary.test.ts` compiles the smallest possible C boundary with Bun 1.4.2 `bun:ffi` and establishes two facts:

- The declared `cstring` argument arrives as a null pointer. It cannot identify an approved cache root.
- An explicitly NUL-terminated `ptr` reaches native code and retains macOS `open` semantics: a directory opens, a file reports `ENOTDIR`, and a missing path reports `ENOENT`.
- Native `openat`/`fstatat(AT_SYMLINK_NOFOLLOW)` sees each entry replacement as a different inode and classifies a symlink without following it. Those primitives work, but Bun does not offer them as a supported package boundary.

The second fact is intentionally not an implementation escape hatch. It proves the primitive only after the JavaScript side has supplied a raw pointer; it does not provide a supported, package-stable ownership or lifetime contract for a security-critical mutation adapter. The test is pinned to the repository Bun 1.4.2 runtime, so a future Bun upgrade must rerun it before revisiting the decision.

## Consequence

Node/Bun filesystem APIs cannot perform descriptor-relative directory enumeration on macOS, and `/dev/fd/<fd>` traversal is known to fail with `ENOTDIR`. The current Bun FFI ABI cannot safely replace that missing boundary. Path-based recursion, shell tools, runtime compiler assumptions, and a pointer-based fallback are therefore rejected.

The existing scan may report the cache, but `createBunCacheOperations` never offers it as selectable and its execution method rejects. This preserves the approval boundary while preventing symlink, entry-swap, mount, permission, and concurrent-mutation paths from reaching deletion.

## Reconsideration criteria

A future implementation needs a supported, packaged macOS native adapter with a stable ABI and native acceptance that proves descriptor-relative `openat`, `fstatat`, and `unlinkat` traversal against root and entry swaps, symlinks, mounts, permissions, concurrent cleanup, and races. Until then, this report-only result is the intended safety behavior.
