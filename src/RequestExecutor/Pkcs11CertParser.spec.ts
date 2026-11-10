import { Pkcs11CertParser } from './Pkcs11CertParser';
import { Pkcs11Cert } from './Pkcs11Cert';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';

describe('Pkcs11CertParser', () => {
  // `it.each` tables are built when the suite is defined, so the fixtures must exist by then.
  const dir = mkdtempSync(join(tmpdir(), 'pkcs11-parser-'));
  const module = join(dir, 'vendor-pkcs11.so');
  const pinFile = join(dir, 'card.pin');
  const certFile = join(dir, 'client.pem');
  writeFileSync(module, '');
  writeFileSync(pinFile, '1234');
  writeFileSync(certFile, '');

  const canMakeFilesUnreadable =
    process.platform !== 'win32' && process.getuid?.() !== 0;

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  describe('parse', () => {
    it('should return no descriptors when no entries are given', () => {
      // act
      const result = Pkcs11CertParser.parse(undefined);

      // assert
      expect(result).toEqual([]);
    });

    it('should apply the defaults to a minimal entry given as a JSON string', () => {
      // arrange
      const entry = JSON.stringify({
        hostname: 'example.com',
        pinFile
      });

      // act
      const result = Pkcs11CertParser.parse([entry]);

      // assert
      expect(result).toEqual([
        {
          hostname: 'example.com',
          port: undefined,
          pinFile,
          token: undefined,
          object: undefined,
          id: undefined,
          cert: 'token',
          maxConcurrency: 1
        }
      ]);
    });

    it('should accept an entry given as an object, as the config file supplies it', () => {
      // arrange
      const entry = {
        hostname: '*.example.com',
        port: 8443,
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
          pinEnv: 'CARD_PIN',
          token: 'Alice PIV',
          object: 'tls-client',
          id: 'ab01',
          cert: certFile,
          maxConcurrency: 2
        }
      ]);
    });

    it('should accept a single object that is not wrapped in an array', () => {
      // act
      const result = Pkcs11CertParser.parse({
        hostname: 'example.com',
        pinFile
      });

      // assert
      expect(result).toEqual([
        expect.objectContaining({ hostname: 'example.com' })
      ]);
    });

    it('should expand a JSON array string, as an environment variable supplies several entries', () => {
      // arrange
      const value = JSON.stringify([
        { hostname: 'a.example.com', pinFile },
        { hostname: 'b.example.com', pinFile }
      ]);

      // act
      const result = Pkcs11CertParser.parse([value]);

      // assert
      expect(result.map((cert: Pkcs11Cert) => cert.hostname)).toEqual([
        'a.example.com',
        'b.example.com'
      ]);
    });

    it('should resolve relative paths to absolute ones', () => {
      // act
      const [result]: Pkcs11Cert[] = Pkcs11CertParser.parse([
        {
          hostname: 'example.com',
          pinFile: relative(process.cwd(), pinFile),
          cert: relative(process.cwd(), certFile)
        }
      ]);

      // assert
      expect(result).toMatchObject({ pinFile, cert: certFile });
    });

    it.each([
      ['no hostname', { pinFile }, /#1: specify "hostname"/],
      [
        'a per-entry module',
        { hostname: 'example.com', module: '/opt/vendor.so', pinFile },
        /"module" is not a per-certificate field.*--pkcs11-module/
      ],
      [
        'a blank hostname',
        { hostname: '  ', pinFile },
        /"hostname" must be a non-empty string/
      ],
      [
        'no PIN source',
        { hostname: 'example.com' },
        /exactly one of "pinFile" or "pinEnv"/
      ],
      [
        'two PIN sources',
        { hostname: 'example.com', pinFile, pinEnv: 'CARD_PIN' },
        /exactly one of "pinFile" or "pinEnv"/
      ],
      [
        'a literal PIN',
        { hostname: 'example.com', pinFile, pin: '1234' },
        /literal "pin" is not accepted/
      ],
      [
        'a misspelled field',
        { hostname: 'example.com', pinFile, pinfile: 'x' },
        /unknown field\(s\) "pinfile"/
      ],
      [
        'an unset PIN variable',
        { hostname: 'example.com', pinEnv: 'MISSING_PIN' },
        /environment variable MISSING_PIN referenced by "pinEnv" is not set/
      ],
      [
        'a PIN variable read by bright-cli itself',
        { hostname: 'example.com', pinEnv: 'REPEATER_CARD_PIN' },
        /starts with "REPEATER"/
      ],
      [
        'a PIN variable read by bright-cli without an underscore',
        { hostname: 'example.com', pinEnv: 'REPEATERPIN' },
        /starts with "REPEATER"/
      ],
      [
        'a missing PIN file',
        { hostname: 'example.com', pinFile: join(dir, 'nope.pin') },
        /"pinFile" .* does not exist/
      ],
      [
        'a missing cert file',
        {
          hostname: 'example.com',
          pinFile,
          cert: join(dir, 'nope.pem')
        },
        /"cert" .* does not exist/
      ],
      [
        'port 0',
        { hostname: 'example.com', pinFile, port: 0 },
        /"port" must be/
      ],
      [
        'a non-numeric port',
        { hostname: 'example.com', pinFile, port: 'abc' },
        /"port" must be/
      ],
      [
        'a non-hex id',
        { hostname: 'example.com', pinFile, id: 'xyz' },
        /"id" must be a hex/
      ],
      [
        'an odd-length id',
        { hostname: 'example.com', pinFile, id: 'abc' },
        /"id" must be a hex/
      ],
      [
        'maxConcurrency 0',
        { hostname: 'example.com', pinFile, maxConcurrency: 0 },
        /"maxConcurrency" must be an integer/
      ],
      [
        'a fractional maxConcurrency',
        { hostname: 'example.com', pinFile, maxConcurrency: 1.5 },
        /"maxConcurrency" must be an integer/
      ]
    ])('should reject an entry with %s', (_case, entry, message) => {
      // act
      const act = () => Pkcs11CertParser.parse([entry], { env: {} });

      // assert
      expect(act).toThrow(message);
    });

    it('should reject a PIN typed into "pinEnv" without repeating it', () => {
      // act
      const act = () =>
        Pkcs11CertParser.parse([{ hostname: 'example.com', pinEnv: '483920' }]);

      // assert
      expect(act).toThrow(/must be the name of an environment variable/);
      expect(act).not.toThrow(/483920/);
    });

    it('should reject "pinEnv" for a daemon, whose service does not inherit the environment', () => {
      // act
      const act = () =>
        Pkcs11CertParser.parse(
          [{ hostname: 'example.com', pinEnv: 'CARD_PIN' }],
          { env: { CARD_PIN: '1234' }, daemon: true }
        );

      // assert
      expect(act).toThrow(/"pinEnv" is not available to the daemon service/);
    });

    it('should reject relative paths when installing the daemon', () => {
      // act
      const act = () =>
        Pkcs11CertParser.parse(
          [
            {
              hostname: 'example.com',
              pinFile: relative(process.cwd(), pinFile)
            }
          ],
          { daemon: true }
        );

      // assert
      expect(act).toThrow(
        /"pinFile" .* must be an absolute path when installing the daemon/
      );
    });

    it('should accept absolute paths when installing the daemon', () => {
      // act
      const result = Pkcs11CertParser.parse(
        [{ hostname: 'example.com', pinFile, cert: certFile }],
        { daemon: true }
      );

      // assert
      expect(result).toHaveLength(1);
    });

    it('should reject a value that is not valid JSON', () => {
      // act
      const act = () => Pkcs11CertParser.parse(['{"hostname":']);

      // assert
      expect(act).toThrow('Option --pkcs11-cert value #1: invalid JSON.');
    });

    it('should reject an entry that is not an object', () => {
      // act
      const act = () => Pkcs11CertParser.parse(['"example.com"']);

      // assert
      expect(act).toThrow('Option --pkcs11-cert #1: expected a JSON object.');
    });

    it('should name the position of the failing entry', () => {
      // arrange
      const entries = [
        { hostname: 'a.example.com', pinFile },
        { hostname: 'b.example.com' }
      ];

      // act
      const act = () => Pkcs11CertParser.parse(entries);

      // assert
      expect(act).toThrow(
        /^Option --pkcs11-cert #2 \(hostname "b.example.com"\)/
      );
    });

    (canMakeFilesUnreadable ? it : it.skip)(
      'should reject a PIN file the process cannot read',
      () => {
        // arrange
        const unreadable = join(dir, 'unreadable.pin');
        writeFileSync(unreadable, '1234');
        chmodSync(unreadable, 0o000);

        // act
        const act = () =>
          Pkcs11CertParser.parse([
            { hostname: 'example.com', pinFile: unreadable }
          ]);

        // assert
        expect(act).toThrow(/"pinFile" .* is not readable/);
      }
    );
  });

  describe('resolveFile', () => {
    it('should return the absolute path of an existing file', () => {
      // act
      const result = Pkcs11CertParser.resolveFile(
        relative(process.cwd(), module),
        'Option --pkcs11-module'
      );

      // assert
      expect(result).toBe(module);
    });

    it('should name the subject when the file does not exist', () => {
      // act
      const act = () =>
        Pkcs11CertParser.resolveFile(
          join(dir, 'missing.so'),
          'Option --pkcs11-provider'
        );

      // assert
      expect(act).toThrow(
        /^Option --pkcs11-provider .*missing\.so does not exist or is not a file\.$/
      );
    });
  });
});
