import { Pkcs11CertParser } from './Pkcs11CertParser';
import { Pkcs11Cert } from './Pkcs11Cert';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('Pkcs11CertParser', () => {
  // `it.each` tables are built when the suite is defined, so the fixtures must exist by then.
  const dir = mkdtempSync(join(tmpdir(), 'pkcs11-parser-'));
  const module = join(dir, 'vendor-pkcs11.so');
  const pinFile = join(dir, 'card.pin');
  const certFile = join(dir, 'client.pem');
  writeFileSync(module, '');
  writeFileSync(pinFile, '1234');
  writeFileSync(certFile, '');

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  describe('parse', () => {
    it('returns no descriptors when no entries are given', () => {
      // act
      const result = Pkcs11CertParser.parse(undefined);

      // assert
      expect(result).toEqual([]);
    });

    it('applies the defaults to a minimal entry given as a JSON string', () => {
      // arrange
      const entry = JSON.stringify({
        hostname: 'example.com',
        module,
        pinFile
      });

      // act
      const result = Pkcs11CertParser.parse([entry]);

      // assert
      expect(result).toEqual([
        {
          hostname: 'example.com',
          port: undefined,
          module,
          pinFile,
          token: undefined,
          object: undefined,
          id: undefined,
          cert: 'token',
          maxConcurrency: 1
        }
      ]);
    });

    it('accepts an entry given as an object, as the config file supplies it', () => {
      // arrange
      const entry = {
        hostname: '*.example.com',
        port: 8443,
        module,
        pinEnv: 'CARD_PIN',
        token: 'Alice PIV',
        object: 'tls-client',
        id: 'AB01',
        cert: certFile,
        maxConcurrency: 2
      };

      // act
      const result = Pkcs11CertParser.parse([entry], {
        env: { CARD_PIN: '1234' }
      });

      // assert
      expect(result).toEqual([
        {
          hostname: '*.example.com',
          port: '8443',
          module,
          pinEnv: 'CARD_PIN',
          token: 'Alice PIV',
          object: 'tls-client',
          id: 'ab01',
          cert: certFile,
          maxConcurrency: 2
        }
      ]);
    });

    it('uses the default module when the entry has none', () => {
      // act
      const [result]: Pkcs11Cert[] = Pkcs11CertParser.parse(
        [{ hostname: 'example.com', pinFile }],
        { defaultModule: module }
      );

      // assert
      expect(result.module).toBe(module);
    });

    it('prefers the module of the entry over the default module', () => {
      // arrange
      const other = join(dir, 'other-pkcs11.so');
      writeFileSync(other, '');

      // act
      const [result]: Pkcs11Cert[] = Pkcs11CertParser.parse(
        [{ hostname: 'example.com', module: other, pinFile }],
        { defaultModule: module }
      );

      // assert
      expect(result.module).toBe(other);
    });

    it.each([
      ['no hostname', { module, pinFile }, /#1: specify "hostname"/],
      [
        'a blank hostname',
        { hostname: '  ', module, pinFile },
        /"hostname" must be a non-empty string/
      ],
      [
        'no module and no default module',
        { hostname: 'example.com', pinFile },
        /#1 \(hostname "example.com"\): specify "module"/
      ],
      [
        'no PIN source',
        { hostname: 'example.com', module },
        /exactly one of "pinFile" or "pinEnv"/
      ],
      [
        'two PIN sources',
        { hostname: 'example.com', module, pinFile, pinEnv: 'CARD_PIN' },
        /exactly one of "pinFile" or "pinEnv"/
      ],
      [
        'a literal PIN',
        { hostname: 'example.com', module, pinFile, pin: '1234' },
        /literal "pin" is not accepted/
      ],
      [
        'a misspelled field',
        { hostname: 'example.com', module, pinFile, pinfile: 'x' },
        /unknown field\(s\) "pinfile"/
      ],
      [
        'an unset PIN variable',
        { hostname: 'example.com', module, pinEnv: 'MISSING_PIN' },
        /"MISSING_PIN" referenced by "pinEnv" is not set/
      ],
      [
        'a missing module file',
        { hostname: 'example.com', module: join(dir, 'nope.so'), pinFile },
        /"module" file .* does not exist/
      ],
      [
        'a missing PIN file',
        { hostname: 'example.com', module, pinFile: join(dir, 'nope.pin') },
        /"pinFile" file .* does not exist/
      ],
      [
        'a missing cert file',
        {
          hostname: 'example.com',
          module,
          pinFile,
          cert: join(dir, 'nope.pem')
        },
        /"cert" file .* does not exist/
      ],
      [
        'port 0',
        { hostname: 'example.com', module, pinFile, port: 0 },
        /"port" must be/
      ],
      [
        'a non-numeric port',
        { hostname: 'example.com', module, pinFile, port: 'abc' },
        /"port" must be/
      ],
      [
        'a non-hex id',
        { hostname: 'example.com', module, pinFile, id: 'xyz' },
        /"id" must be a hex/
      ],
      [
        'an odd-length id',
        { hostname: 'example.com', module, pinFile, id: 'abc' },
        /"id" must be a hex/
      ],
      [
        'maxConcurrency 0',
        { hostname: 'example.com', module, pinFile, maxConcurrency: 0 },
        /"maxConcurrency" must be an integer/
      ],
      [
        'a fractional maxConcurrency',
        { hostname: 'example.com', module, pinFile, maxConcurrency: 1.5 },
        /"maxConcurrency" must be an integer/
      ]
    ])('rejects an entry with %s', (_case, entry, message) => {
      // act
      const act = () => Pkcs11CertParser.parse([entry], { env: {} });

      // assert
      expect(act).toThrow(message);
    });

    it('rejects an entry that is not valid JSON', () => {
      // act
      const act = () => Pkcs11CertParser.parse(['{"hostname":']);

      // assert
      expect(act).toThrow('Option --pkcs11-cert #1: invalid JSON.');
    });

    it('rejects an entry that is not an object', () => {
      // act
      const act = () => Pkcs11CertParser.parse(['["example.com"]']);

      // assert
      expect(act).toThrow('Option --pkcs11-cert #1: expected a JSON object.');
    });

    it('names the position of the failing entry', () => {
      // arrange
      const entries = [
        { hostname: 'a.example.com', module, pinFile },
        { hostname: 'b.example.com', pinFile }
      ];

      // act
      const act = () => Pkcs11CertParser.parse(entries);

      // assert
      expect(act).toThrow(
        /^Option --pkcs11-cert #2 \(hostname "b.example.com"\)/
      );
    });

    it('rejects a pin file the process cannot read', () => {
      // arrange
      if (process.platform === 'win32' || process.getuid?.() === 0) {
        return;
      }
      const unreadable = join(dir, 'unreadable.pin');
      writeFileSync(unreadable, '1234');
      chmodSync(unreadable, 0o000);

      // act
      const act = () =>
        Pkcs11CertParser.parse([
          { hostname: 'example.com', module, pinFile: unreadable }
        ]);

      // assert
      expect(act).toThrow(/"pinFile" .* is not readable/);
    });
  });
});
