# Native Trash boundary decision

## Decision

`@ankhorage/osx` keeps orphaned application remnants report-only. It does not provide a Trash
adapter, a path-based rename fallback, or an executable `storage orphans clean` command.

This is a fail-closed decision, not an implementation delay: the macOS APIs available to this
package cannot bind the inode that was inspected and approved to the object renamed at mutation
time. The approval boundary therefore cannot truthfully guarantee that it moves the approved
object.

## Reproducible native acceptance

`tests/nativeTrashBoundary.test.ts` compiles and runs
`tests/fixtures/native/renameatx-source-identity-probe.c` on Darwin. The probe:

1. opens source and destination parent directories and records the approved source `st_dev` and
   `st_ino` with `fstatat`;
2. replaces only the final source directory entry with a different directory;
3. calls `renameatx_np(sourceDirectoryFd, "approved", trashDirectoryFd, "recovery",
RENAME_EXCL | RENAME_NOFOLLOW_ANY | RENAME_RESOLVE_BENEATH)`; and
4. asserts that the destination contains the replacement inode, not the verified inode.

The test passes only when the unsafe substitution is observed. It is an executable proof that
directory descriptors and the strongest relevant `renameatx_np` flags do not supply source inode
binding. It makes no user Trash mutation; all fixture directories are private temporary paths.

## Native API guarantees and limits

The Darwin `rename(2)` manual documents these relevant facts:

- `renameat` and `renameatx_np` resolve relative names beneath the supplied directory descriptors.
  A stable destination-parent descriptor prevents a later replacement of the textual `~/.Trash`
  path from redirecting the destination.
- `RENAME_EXCL` makes an existing destination fail rather than overwrite it, when supported by the
  destination filesystem. The adapter would have to query the volume capability first.
- `RENAME_NOFOLLOW_ANY` rejects a symbolic link encountered while resolving either path. It does
  not turn the final source name into an inode handle.
- `RENAME_RESOLVE_BENEATH` rejects paths that escape their supplied starting directory. It confines
  resolution but also does not bind the final source name to a prior `fstatat` result.
- `RENAME_SWAP` is atomic only for two names that already exist. It neither preserves the approved
  source identity nor creates a safe recovery destination. `RENAME_EXCL` and `RENAME_SWAP` cannot
  be combined.
- `rename` is atomic with respect to the namespace result and keeps an instance of the destination
  name across a crash. That is not an atomic compare-and-rename of a previously observed inode.
- both objects must be on the same filesystem. `EXDEV` is not a safe reason to copy-and-delete;
  copy, recursive traversal, and unlink create more unbound mutation windows and are prohibited.

The SDK declaration is in `sys/stdio.h`; the host manual page is available as `man 2 rename`.
Neither exposes an operation equivalent to “rename this open file descriptor only if it is still
the directory entry named `approved`”. `open` plus `fstat`, an additional `fstatat`, advisory
locks, or serializing this process all leave an attacker-controlled interval before `renameatx_np`.

## Threat model and required invariants

The caller, scanner, and approval UI are trusted only to select a snapshot. The filesystem
namespace below a candidate and its Trash destination is adversarial until an OS primitive binds
the approved identity to the mutation. A same-user process, login item, sync client, installer, or
concurrent application can alter it between operations.

| Scenario                       | What descriptor-based `renameatx_np` prevents                         | Remaining reason mutation is unavailable                                                                                              |
| ------------------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Source final-name swap         | Parent-directory replacement                                          | The final name may denote a different inode after approval.                                                                           |
| Source or destination symlink  | Resolution through any encountered symlink with `RENAME_NOFOLLOW_ANY` | No symlink does not prove the final source inode is the one approved.                                                                 |
| Destination/Trash path swap    | Destination parent descriptor avoids reopening `~/.Trash` by path     | A new destination name still needs `RENAME_EXCL`; source identity remains unbound.                                                    |
| Existing destination collision | `RENAME_EXCL`, on a supporting filesystem                             | Collision handling does not bind source identity or guarantee recovery.                                                               |
| Hardlink/multi-owner source    | Nothing                                                               | A link count can change after inspection; moving one name would not establish exclusive ownership.                                    |
| Mount or filesystem transition | Same-filesystem requirement exposes `EXDEV`                           | Mount state/capabilities can change; copying is not an acceptable fallback.                                                           |
| Concurrent tree change         | Atomic namespace rename of whichever final name resolves              | Tree contents, ownership, ACLs, and inode identity are not atomically revalidated with the rename.                                    |
| App ownership provenance       | Nothing                                                               | Bundle ID, directory name, manifest, absence from inventories, and missing installation are signals, never exclusive ownership proof. |

Any future mutable adapter must prove all of these properties before it is composed into
`StorageOperations`:

1. a positive, authoritative exclusive-ownership provenance that remains valid at the mutation
   boundary, rather than inferred absence;
2. source object identity binding through the mutation, including final-component replacement,
   hardlink, symlink, mount, and concurrent-modification adversarial acceptance;
3. destination identity binding, collision-safe creation, same-filesystem verification, and a
   durable recovery record that exists only after the move succeeds; and
4. per-path approval immediately before the irreversible boundary, explicit errors with no
   cleanup fallback, and accounting that distinguishes moved bytes from free-space change.

## Verifiable alternatives

The safe currently available alternatives are read-only reporting and asking the user to move a
specific item through Finder. A future design may use a macOS security-scoped or Finder-mediated
API only if its documented contract provides identity-bound transfer and recovery semantics, and
then must add a native adversarial acceptance suite for those guarantees. Until such a contract is
available, no `rename`, `renameat`, `renameatx_np`, `FileManager`, shell, recursive-delete, or
copy-and-delete path is eligible for this capability.
