import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { promisify } from 'node:util';

/*** Read an application bundle identifier through macOS Plist parsing, including binary manifests. */
export async function readApplicationBundleIdAsync(application: string): Promise<string | null> {
  try {
    const result = await promisify(execFile)(
      '/usr/bin/plutil',
      [
        '-extract',
        'CFBundleIdentifier',
        'raw',
        '-o',
        '-',
        '--',
        join(application, 'Contents', 'Info.plist'),
      ],
      { timeout: 10_000, maxBuffer: 2_000_000 },
    );
    const bundleId = result.stdout.trim();
    return bundleId === '' ? null : bundleId;
  } catch {
    return null;
  }
}
