import { CliInfo } from './CliInfo';

describe('CliInfo', () => {
  const uuid =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

  it('should assign a random UUID v4 as the instance ID', () => {
    // act
    const info = new CliInfo(process.cwd());

    // assert
    expect(info.instanceId).toMatch(uuid);
  });

  it('should assign a different instance ID to every process', () => {
    // act
    const first = new CliInfo(process.cwd());
    const second = new CliInfo(process.cwd());

    // assert
    expect(first.instanceId).not.toBe(second.instanceId);
  });
});
