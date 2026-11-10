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

  public load(path: string): Pkcs11Module {
    let module = this.modules.get(path);

    if (!module) {
      module = this.initialize(path);
      this.modules.set(path, module);
    }

    return module;
  }

  private initialize(path: string): Pkcs11Module {
    // Loaded on demand so the native addon is only required when PKCS#11 is used.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const binding: Pkcs11jsBinding = require('pkcs11js');
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
