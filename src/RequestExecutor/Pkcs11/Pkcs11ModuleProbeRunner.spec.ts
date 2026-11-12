import { Pkcs11ProbeLoaded } from './Pkcs11ModuleProbe';
import { Pkcs11ModuleProbeRunner, SpawnProbe } from './Pkcs11ModuleProbeRunner';

describe('Pkcs11ModuleProbeRunner', () => {
  const MODULE =
    'C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll';
  const loaded: Pkcs11ProbeLoaded = {
    ok: true,
    library: 'Yubico YKCS11',
    tokens: []
  };

  const runner = (spawn: SpawnProbe, env: NodeJS.ProcessEnv = {}) =>
    new Pkcs11ModuleProbeRunner({
      spawn,
      env,
      platform: 'win32',
      timeoutMs: 15_000,
      self: () => ({ command: 'C:\\Bright\\bright-cli.exe', args: [] })
    });

  const answer = (
    overrides: Partial<ReturnType<SpawnProbe>> = {}
  ): jest.MockedFunction<SpawnProbe> =>
    jest.fn<ReturnType<SpawnProbe>, Parameters<SpawnProbe>>(() => ({
      status: 0,
      signal: null,
      error: undefined,
      stdout: `PKCS11_PROBE_RESULT ${JSON.stringify(loaded)}\n`,
      ...overrides
    }));

  describe('probe', () => {
    it('should start this CLI with the probe argument and the library path', () => {
      // arrange
      const spawn = answer();

      // act
      runner(spawn).probe(MODULE);

      // assert
      expect(spawn).toHaveBeenCalledWith(
        'C:\\Bright\\bright-cli.exe',
        ['__pkcs11-probe', MODULE],
        expect.objectContaining({
          timeout: 15_000,
          windowsHide: true,
          shell: false
        })
      );
    });

    it("should put the library's folder first in the child's PATH, keeping the variable's name", () => {
      // arrange
      const spawn = answer();

      // act
      runner(spawn, { Path: 'C:\\Windows', SOFTHSM2_CONF: 'C:\\t.conf' }).probe(
        MODULE
      );

      // assert
      const { env } = spawn.mock.calls[0][2];
      expect(env).toEqual({
        Path: 'C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin;C:\\Windows',
        SOFTHSM2_CONF: 'C:\\t.conf'
      });
    });

    it('should return the result printed among other output', () => {
      // arrange
      const spawn = answer({
        stdout: `[notice] something\r\nPKCS11_PROBE_RESULT ${JSON.stringify(
          loaded
        )}\r\n`
      });

      // act
      const result = runner(spawn).probe(MODULE);

      // assert
      expect(result).toEqual(loaded);
    });

    it('should report a timeout', () => {
      // arrange
      const error = Object.assign(new Error('spawnSync ETIMEDOUT'), {
        code: 'ETIMEDOUT'
      });

      // act
      const result = runner(
        answer({ error, status: null, signal: 'SIGKILL', stdout: '' })
      ).probe(MODULE);

      // assert
      expect(result).toEqual({
        ok: false,
        reason: 'timeout',
        detail: 'no answer within 15 s'
      });
    });

    it('should report a crash with the exit code in hex', () => {
      // act
      const result = runner(answer({ status: 3221225477, stdout: '' })).probe(
        MODULE
      );

      // assert
      expect(result).toEqual({
        ok: false,
        reason: 'crashed',
        detail: 'the probe process exited with code 0xC0000005'
      });
    });

    it('should report a crash when no result was printed', () => {
      // act
      const result = runner(answer({ stdout: 'garbage' })).probe(MODULE);

      // assert
      expect(result).toMatchObject({ ok: false, reason: 'crashed' });
    });

    it('should report a process that could not start', () => {
      // act
      const result = runner(
        answer({ error: new Error('spawnSync EACCES'), status: null })
      ).probe(MODULE);

      // assert
      expect(result).toEqual({
        ok: false,
        reason: 'crashed',
        detail: 'spawnSync EACCES'
      });
    });
  });
});
