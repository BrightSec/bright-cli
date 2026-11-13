import { resolvePkcs11ModuleCandidates } from './Pkcs11ModuleCandidates';

describe('resolvePkcs11ModuleCandidates', () => {
  const env: NodeJS.ProcessEnv = {
    'ProgramFiles': 'C:\\Program Files',
    'ProgramFiles(x86)': 'C:\\Program Files (x86)',
    'SystemRoot': 'C:\\Windows'
  };

  it('should try the SafeNet Authentication Client IDPrime library first on Windows', () => {
    // act
    const first = resolvePkcs11ModuleCandidates('win32', env)[0];

    // assert
    expect(first).toMatchObject({
      product: 'Thales SafeNet Authentication Client (IDPrime)',
      x64: [
        'C:\\Program Files\\SafeNet\\Authentication\\SAC\\x64\\IDPrimePKCS1164.dll'
      ],
      x86: [
        'C:\\Program Files\\SafeNet\\Authentication\\SAC\\x32\\IDPrimePKCS11.dll'
      ]
    });
  });

  it('should try OpenSC last on Windows', () => {
    // act
    const result = resolvePkcs11ModuleCandidates('win32', env);

    // assert
    expect(result[result.length - 1]).toMatchObject({
      product: 'OpenSC',
      x64: [
        'C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll',
        'C:\\Windows\\System32\\opensc-pkcs11.dll'
      ]
    });
  });

  it('should list only absolute paths under the system and program folders', () => {
    // act
    const paths = resolvePkcs11ModuleCandidates('win32', env).flatMap(
      ({ x64, x86 }) => [...x64, ...x86]
    );

    // assert
    expect(paths.length).toBeGreaterThan(0);
    expect(
      paths.filter(
        (path: string) =>
          !/^C:\\(Program Files|Program Files \(x86\)|Windows)\\/.test(path)
      )
    ).toEqual([]);
  });

  it('should read the variables regardless of their case', () => {
    // act
    const first = resolvePkcs11ModuleCandidates('win32', {
      PROGRAMFILES: 'D:\\Apps'
    })[0];

    // assert
    expect(first.x64).toEqual([
      'D:\\Apps\\SafeNet\\Authentication\\SAC\\x64\\IDPrimePKCS1164.dll'
    ]);
  });

  it('should leave out the paths whose variable is not set', () => {
    // act
    const result = resolvePkcs11ModuleCandidates('win32', {
      ProgramFiles: 'C:\\Program Files'
    });

    // assert
    expect(
      result.flatMap(({ x64, x86 }) => [...x64, ...x86]).join('\n')
    ).not.toMatch(/Windows|\(x86\)|%/);
  });

  it.each([
    { name: 'a relative path', value: 'Program Files' },
    { name: 'a network path', value: '\\\\server\\share' }
  ])('should leave out the paths whose variable holds $name', ({ value }) => {
    // act
    const result = resolvePkcs11ModuleCandidates('win32', {
      ProgramFiles: value,
      SystemRoot: 'C:\\Windows'
    });

    // assert
    expect(
      result
        .flatMap(({ x64, x86 }) => [...x64, ...x86])
        .every((path: string) => path.startsWith('C:\\Windows\\'))
    ).toBe(true);
  });

  it.each(['linux', 'darwin'] as NodeJS.Platform[])(
    'should have no candidates on %s',
    (platform: NodeJS.Platform) => {
      // act
      const result = resolvePkcs11ModuleCandidates(platform, env);

      // assert
      expect(result).toEqual([]);
    }
  );

  it('should expand candidates given explicitly', () => {
    // act
    const result = resolvePkcs11ModuleCandidates('linux', { HOME: '/home/u' }, [
      { product: 'Vendor', x64: ['%HOME%/lib/vendor.so'], x86: [] }
    ]);

    // assert
    expect(result).toEqual([
      { product: 'Vendor', x64: ['/home/u/lib/vendor.so'], x86: [] }
    ]);
  });
});
