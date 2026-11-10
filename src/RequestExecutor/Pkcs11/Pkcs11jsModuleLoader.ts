import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';
import {
  Pkcs11Module,
  Pkcs11ModuleError,
  Pkcs11ModuleLoader
} from './Pkcs11Module';
import {
  Pkcs11jsBinding,
  Pkcs11jsModule,
  toModuleError
} from './Pkcs11jsModule';

/** Loads modules through the `pkcs11js` native binding. */
export class Pkcs11jsModuleLoader implements Pkcs11ModuleLoader {
  private readonly modules = new Map<string, Pkcs11Module>();

  // An optional dependency compiled at install time: without build tools the
  // install skips it, and only PKCS#11 users need it.
  private static binding(): Pkcs11jsBinding {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires, import/no-extraneous-dependencies
      return require('pkcs11js');
    } catch (e) {
      throw new Pkcs11Error(
        Pkcs11ErrorCode.MODULE_LOAD_FAILED,
        `The pkcs11js native addon is not available (${e?.message}). It is built when bright-cli is installed from npm; reinstall with Python and a C++ compiler available, or use the standalone executable.`
      );
    }
  }

  public load(path: string): Pkcs11Module {
    let module = this.modules.get(path);

    if (!module) {
      module = this.initialize(path);
      this.modules.set(path, module);
    }

    return module;
  }

  private initialize(path: string): Pkcs11Module {
    const binding = Pkcs11jsModuleLoader.binding();
    const lib = new binding.PKCS11();

    try {
      lib.load(path);
    } catch (e) {
      throw new Pkcs11ModuleError('CKR_LIBRARY_LOAD_FAILED', e?.message);
    }

    try {
      lib.C_Initialize();
    } catch (e) {
      const error = toModuleError(e);

      // The OpenSSL provider may already have initialized the same module.
      if (error.ckr !== 'CKR_CRYPTOKI_ALREADY_INITIALIZED') {
        throw error;
      }
    }

    return new Pkcs11jsModule(binding, lib);
  }
}
