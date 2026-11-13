import { readBinaryArch, ReadBytes } from './BinaryArch';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('readBinaryArch', () => {
  const pe = (machine: number, peOffset: number = 0x80): Buffer => {
    const buffer = Buffer.alloc(peOffset + 0x20);
    buffer.write('MZ', 0, 'latin1');
    buffer.writeUInt32LE(peOffset, 0x3c);
    buffer.write('PE\0\0', peOffset, 'latin1');
    buffer.writeUInt16LE(machine, peOffset + 4);

    return buffer;
  };

  const from =
    (buffer: Buffer): ReadBytes =>
    (_: string, position: number, length: number) =>
      buffer.subarray(position, position + length);

  it.each([
    { machine: 0x8664, expected: 'x64' },
    { machine: 0x014c, expected: 'x86' },
    { machine: 0xaa64, expected: 'arm64' },
    { machine: 0x01c4, expected: 'other' }
  ])(
    'should return $expected for PE machine $machine',
    ({ machine, expected }) => {
      // act
      const result = readBinaryArch('lib.dll', from(pe(machine)));

      // assert
      expect(result).toBe(expected);
    }
  );

  it('should follow a PE header that starts beyond the first 4 KB', () => {
    // act
    const result = readBinaryArch('lib.dll', from(pe(0x8664, 0x2000)));

    // assert
    expect(result).toBe('x64');
  });

  it.each([
    {
      name: 'an ELF file',
      buffer: Buffer.from('\x7fELF\x02\x01\x01', 'latin1')
    },
    { name: 'an empty file', buffer: Buffer.alloc(0) },
    { name: 'a truncated PE file', buffer: pe(0x8664).subarray(0, 0x82) }
  ])('should return unknown for $name', ({ buffer }) => {
    // act
    const result = readBinaryArch('lib.dll', from(buffer));

    // assert
    expect(result).toBe('unknown');
  });

  it('should return unknown when the file cannot be read', () => {
    // act
    const result = readBinaryArch('lib.dll', () => {
      throw new Error('EACCES');
    });

    // assert
    expect(result).toBe('unknown');
  });

  it('should read the header from disk by default', () => {
    // arrange
    const dir = mkdtempSync(join(tmpdir(), 'binary-arch-'));
    const path = join(dir, 'lib.dll');
    writeFileSync(path, pe(0x014c));

    try {
      // act
      const result = readBinaryArch(path);

      // assert
      expect(result).toBe('x86');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
