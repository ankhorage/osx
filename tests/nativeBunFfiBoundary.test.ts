import { expect, test } from 'bun:test';
import { cc } from 'bun:ffi';
import { mkdtemp, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/*** Prove the Bun 1.4.2 FFI ABI boundary cannot safely carry cache-root strings. */
test.if(process.platform === 'darwin')(
  'rejects Bun FFI cstring arguments while explicit pointers retain native descriptor errors',
  async () => {
    const fixture = await mkdtemp(join(await realpath(tmpdir()), 'osx-bun-ffi-boundary-'));
    try {
      const file = join(fixture, 'entry');
      await writeFile(file, 'fixture');
      const native = cc({
        source: new URL('./fixtures/native/bun-ffi-boundary-probe.c', import.meta.url),
        symbols: {
          ankh_ffi_cstring_probe: { args: ['cstring'], returns: 'cstring' },
          ankh_ffi_directory_probe: { args: ['ptr'], returns: 'cstring' },
          ankh_ffi_entry_probe: { args: ['ptr', 'ptr'], returns: 'cstring' },
        },
      });
      expect(native.symbols.ankh_ffi_cstring_probe(fixture)).toBe('null');
      expect(native.symbols.ankh_ffi_directory_probe(cString(fixture))).toBe('directory');
      expect(native.symbols.ankh_ffi_directory_probe(cString(file))).toBe('ENOTDIR');
      expect(native.symbols.ankh_ffi_directory_probe(cString(join(fixture, 'missing')))).toBe(
        'ENOENT',
      );
      const replacement = join(fixture, 'replacement');
      const before = native.symbols.ankh_ffi_entry_probe(cString(fixture), cString('entry'));
      await writeFile(replacement, 'replacement');
      await rename(replacement, file);
      const after = native.symbols.ankh_ffi_entry_probe(cString(fixture), cString('entry'));
      expect(after).not.toBe(before);
      await rm(file);
      await symlink(join(fixture, 'missing'), file);
      expect(native.symbols.ankh_ffi_entry_probe(cString(fixture), cString('entry'))).toBe(
        'symlink',
      );
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  },
);

/*** Supply an explicit NUL-terminated pointer because Bun 1.4.2 cstring is not usable here. */
function cString(value: string): Buffer {
  return Buffer.concat([Buffer.from(value), Buffer.of(0)]);
}
