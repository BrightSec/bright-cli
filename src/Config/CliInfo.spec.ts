import { CliInfo } from './CliInfo';

describe('CliInfo', () => {
  it('should assign 8 random hex characters as the instance ID', () => {
    // act
    const info = new CliInfo(process.cwd());

    // assert
    expect(info.instanceId).toMatch(/^[0-9a-f]{8}$/);
  });

  it('should assign a different instance ID to every process', () => {
    // act
    const first = new CliInfo(process.cwd());
    const second = new CliInfo(process.cwd());

    // assert
    expect(first.instanceId).not.toBe(second.instanceId);
  });
});
