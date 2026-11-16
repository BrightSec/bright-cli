process.env.UV_THREADPOOL_SIZE = String(1024);
import 'reflect-metadata';
import {
  PollingScanStatus,
  RetestScan,
  RunRepeater,
  RunScan,
  StopScan,
  UploadArchive,
  VersionCommand,
  Configure,
  GetEntryPoints,
  RunMcpServer
} from './Commands';
import { CliBuilder } from './Config';
import container from './container';
import { RunDiscovery } from './Commands/RunDiscovery';
import { StopDiscovery } from './Commands/StopDiscovery';
import { RerunDiscovery } from './Commands/RerunDiscovery';
import { PollingDiscoveryStatus } from './Commands/PollingDiscoveryStatus';
import { PollingHostUpdateJobStatus } from './Commands/PollingHostUpdateJobStatus';
import { EntryPointsUpdateHost } from './Commands/EntryPointsUpdateHost';
import { Pkcs11ModuleProbe } from './RequestExecutor/Pkcs11/Pkcs11ModuleProbe';

// The Repeater starts itself with this argument to try a PKCS#11 library in a
// throwaway process; it bypasses yargs, so no config, Sentry or network setup runs.
if (process.argv[2] === Pkcs11ModuleProbe.COMMAND) {
  new Pkcs11ModuleProbe().run(process.argv.slice(3), (text: string) =>
    process.stdout.write(text, () => process.exit(0))
  );
} else {
  container.resolve(CliBuilder).build({
    commands: [
      new RunRepeater(),
      new VersionCommand(),
      new PollingScanStatus(),
      new RunScan(),
      new RetestScan(),
      new StopScan(),
      new RunDiscovery(),
      new StopDiscovery(),
      new RerunDiscovery(),
      new PollingDiscoveryStatus(),
      new PollingHostUpdateJobStatus(),
      new UploadArchive(),
      new Configure(),
      new GetEntryPoints(),
      new EntryPointsUpdateHost(),
      new RunMcpServer()
    ]
  }).argv;
}
