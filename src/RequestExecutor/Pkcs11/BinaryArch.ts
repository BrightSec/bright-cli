import { closeSync, openSync, readSync } from 'node:fs';

export type BinaryArch = 'x64' | 'x86' | 'arm64' | 'other' | 'unknown';

export type ReadBytes = (
  path: string,
  position: number,
  length: number
) => Buffer;

const PE_MACHINES: Readonly<Record<number, BinaryArch>> = {
  0x8664: 'x64',
  0x014c: 'x86',
  0xaa64: 'arm64'
};

const readBytes: ReadBytes = (
  path: string,
  position: number,
  length: number
): Buffer => {
  const fd = openSync(path, 'r');

  try {
    const buffer = Buffer.alloc(length);
    const read = readSync(fd, buffer, 0, length, position);

    return buffer.subarray(0, read);
  } finally {
    closeSync(fd);
  }
};

/**
 * Reads the target machine from a PE (Windows DLL/EXE) header without loading the file.
 *
 * @returns `unknown` for anything that is not a readable PE file.
 */
export const readBinaryArch = (
  path: string,
  read: ReadBytes = readBytes
): BinaryArch => {
  try {
    const dos = read(path, 0, 0x40);

    if (dos.length < 0x40 || dos.toString('latin1', 0, 2) !== 'MZ') {
      return 'unknown';
    }

    const peOffset = dos.readUInt32LE(0x3c);
    const pe = read(path, peOffset, 6);

    if (pe.length < 6 || pe.toString('latin1', 0, 4) !== 'PE\0\0') {
      return 'unknown';
    }

    return PE_MACHINES[pe.readUInt16LE(4)] ?? 'other';
  } catch {
    return 'unknown';
  }
};
