export interface RepeaterLauncher {
  loadCerts(cacert?: string): Promise<void>;

  loadScripts(scripts: Record<string, string>): Promise<void>;

  run(repeaterId: string, asDaemon?: boolean): Promise<void>;

  close(): Promise<void>;

  uninstall(): Promise<void>;

  /** @param extraArgs appended to the service's command line, after the current arguments. */
  install(extraArgs?: string[]): Promise<void>;
}

export const RepeaterLauncher: unique symbol = Symbol('RepeaterLauncher');
