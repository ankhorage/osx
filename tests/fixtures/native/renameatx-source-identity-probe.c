#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/stdio.h>
#include <unistd.h>

static int fail(const char *operation) {
  perror(operation);
  return 1;
}

int main(void) {
  char root[] = "/tmp/osx-renameatx-identity.XXXXXX";
  if (mkdtemp(root) == NULL) return fail("mkdtemp");

  char source_parent[1024];
  char trash_parent[1024];
  snprintf(source_parent, sizeof(source_parent), "%s/source", root);
  snprintf(trash_parent, sizeof(trash_parent), "%s/trash", root);
  if (mkdir(source_parent, 0700) != 0 || mkdir(trash_parent, 0700) != 0) return fail("mkdir");

  char approved_path[1024];
  char replacement_path[1024];
  char previous_path[1024];
  snprintf(approved_path, sizeof(approved_path), "%s/approved", source_parent);
  snprintf(replacement_path, sizeof(replacement_path), "%s/replacement", source_parent);
  snprintf(previous_path, sizeof(previous_path), "%s/approved-before-swap", source_parent);
  if (mkdir(approved_path, 0700) != 0 || mkdir(replacement_path, 0700) != 0)
    return fail("mkdir source");

  const int source_fd = open(source_parent, O_RDONLY | O_DIRECTORY);
  const int trash_fd = open(trash_parent, O_RDONLY | O_DIRECTORY);
  if (source_fd < 0 || trash_fd < 0) return fail("open parent");

  struct stat approved;
  struct stat replacement;
  struct stat moved;
  if (fstatat(source_fd, "approved", &approved, AT_SYMLINK_NOFOLLOW) != 0) return fail("fstatat approved");
  if (fstatat(source_fd, "replacement", &replacement, AT_SYMLINK_NOFOLLOW) != 0)
    return fail("fstatat replacement");

  /* An adversary replaces only the final source name after application verification. */
  if (renameat(source_fd, "approved", source_fd, "approved-before-swap") != 0)
    return fail("rename approved aside");
  if (renameat(source_fd, "replacement", source_fd, "approved") != 0)
    return fail("rename replacement into approved name");

  if (renameatx_np(
        source_fd,
        "approved",
        trash_fd,
        "recovery",
        RENAME_EXCL | RENAME_NOFOLLOW_ANY | RENAME_RESOLVE_BENEATH
      ) != 0)
    return fail("renameatx_np");
  if (fstatat(trash_fd, "recovery", &moved, AT_SYMLINK_NOFOLLOW) != 0)
    return fail("fstatat recovery");

  const int moved_replacement = moved.st_dev == replacement.st_dev && moved.st_ino == replacement.st_ino;
  const int moved_approved = moved.st_dev == approved.st_dev && moved.st_ino == approved.st_ino;
  if (!moved_replacement || moved_approved) {
    fprintf(stderr, "renameatx_np unexpectedly bound the verified source inode\n");
    return 1;
  }

  puts("final-source-name-swap-was-moved");
  close(source_fd);
  close(trash_fd);
  if (rmdir(previous_path) != 0) return fail("rmdir source entry");
  char recovery_path[1024];
  snprintf(recovery_path, sizeof(recovery_path), "%s/recovery", trash_parent);
  if (rmdir(recovery_path) != 0 || rmdir(source_parent) != 0 || rmdir(trash_parent) != 0 || rmdir(root) != 0)
    return fail("rmdir fixture");
  return 0;
}
