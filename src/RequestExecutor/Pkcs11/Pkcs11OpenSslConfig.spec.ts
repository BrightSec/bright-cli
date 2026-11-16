import { Pkcs11OpenSslConfig } from './Pkcs11OpenSslConfig';
import { readFileSync, rmSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

describe('Pkcs11OpenSslConfig', () => {
  describe('providerName', () => {
    it.each([
      { provider: 'C:/Bright/pkcs11prov.dll', expected: 'pkcs11prov' },
      {
        provider: '/opt/homebrew/lib/ossl-modules/pkcs11prov.dylib',
        expected: 'pkcs11prov'
      },
      {
        provider: '/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so',
        expected: 'pkcs11'
      },
      { provider: '/opt/pkcs11-provider.so', expected: 'pkcs11' }
    ])(
      'should name $provider $expected',
      ({ provider, expected }: { provider: string; expected: string }) => {
        // act
        const result = Pkcs11OpenSslConfig.providerName(provider);

        // assert
        expect(result).toBe(expected);
      }
    );
  });

  describe('render', () => {
    it('should declare the provider under its own name', () => {
      // act
      const { content, name } = Pkcs11OpenSslConfig.render(
        '/usr/lib/ossl-modules/pkcs11.so',
        '/opt/vendor.so'
      );

      // assert
      expect(name).toBe('pkcs11');
      expect(content).toBe(
        [
          'openssl_conf = openssl_init',
          '[openssl_init]',
          'providers = provider_sect',
          '[provider_sect]',
          'default = default_sect',
          'pkcs11 = pkcs11_sect',
          '[default_sect]',
          'activate = 1',
          '[pkcs11_sect]',
          'module = /usr/lib/ossl-modules/pkcs11.so',
          'pkcs11_module = /opt/vendor.so',
          'pkcs11-module-path = /opt/vendor.so',
          'pkcs11-module-quirks = no-deinit',
          'activate = 1',
          ''
        ].join('\n')
      );
    });

    it('should write Windows paths with forward slashes', () => {
      // act
      const { content } = Pkcs11OpenSslConfig.render(
        'C:\\Program Files\\Bright\\pkcs11prov.dll',
        'C:\\Windows\\System32\\vendor-pkcs11.dll'
      );

      // assert
      expect(content).toContain(
        'module = C:/Program Files/Bright/pkcs11prov.dll'
      );
      expect(content).toContain(
        'pkcs11_module = C:/Windows/System32/vendor-pkcs11.dll'
      );
    });

    it.each([
      '/opt/a#b.so',
      '/opt/$HOME.so',
      '/opt/a;b.so',
      '/opt/"a".so',
      '/opt/a\nb.so'
    ])('should reject the module path %j', (module: string) => {
      // act
      const act = () => Pkcs11OpenSslConfig.render('/p.so', module);

      // assert
      expect(act).toThrow('contains a character OpenSSL cannot read');
    });
  });

  describe('write', () => {
    it('should write the config to a private temporary file', () => {
      // act
      const { path, name } = Pkcs11OpenSslConfig.write(
        '/p/pkcs11prov.so',
        '/opt/a.so'
      );

      // assert
      try {
        expect(readFileSync(path, 'utf8')).toContain(
          'pkcs11_module = /opt/a.so'
        );
        expect(name).toBe('pkcs11prov');

        if (process.platform !== 'win32') {
          expect(statSync(path).mode % 0o1000).toBe(0o600);
          expect(statSync(dirname(path)).mode % 0o1000).toBe(0o700);
        }
      } finally {
        rmSync(dirname(path), { recursive: true, force: true });
      }
    });
  });
});
