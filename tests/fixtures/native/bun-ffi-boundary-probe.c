#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static char result[32];

const char *ankh_ffi_cstring_probe(const char *value) {
  snprintf(result, sizeof(result), "%s", value == NULL ? "null" : "non-null");
  return result;
}

const char *ankh_ffi_directory_probe(const char *path) {
  const int descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor >= 0) {
    close(descriptor);
    snprintf(result, sizeof(result), "directory");
  } else if (errno == ENOTDIR) {
    snprintf(result, sizeof(result), "ENOTDIR");
  } else if (errno == ENOENT) {
    snprintf(result, sizeof(result), "ENOENT");
  } else {
    snprintf(result, sizeof(result), "other");
  }
  return result;
}

const char *ankh_ffi_entry_probe(const char *directory_path, const char *name) {
  const int directory = open(directory_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat entry;
  if (directory < 0 || fstatat(directory, name, &entry, AT_SYMLINK_NOFOLLOW) != 0) {
    if (directory >= 0) close(directory);
    snprintf(result, sizeof(result), "missing");
    return result;
  }
  close(directory);
  if (S_ISLNK(entry.st_mode)) {
    snprintf(result, sizeof(result), "symlink");
  } else {
    snprintf(result, sizeof(result), "%llu", (unsigned long long)entry.st_ino);
  }
  return result;
}
