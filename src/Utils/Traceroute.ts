import { Helpers } from './Helpers';
import { logger } from './Logger';
import raw from '@brightsec/raw-socket';
import dgram from 'node:dgram';
import { Resolver } from 'node:dns/promises';
import { EventEmitter, once } from 'node:events';
import { isIP } from 'node:net';

export { Protocol } from '@brightsec/raw-socket';

const Stop: unique symbol = Symbol('Stop');

interface ReturnType {
  reached: boolean;
}

export interface Options {
  amountProbes: number;
  maximumHops: number;
  timeoutInMillis: number;
  reverseLookup: boolean;
  protocol: number;
  packetSize: number;
  outStream: typeof process.stdout;
}

const defaultOptions: Options = {
  amountProbes: 3,
  maximumHops: 64,
  timeoutInMillis: 3000,
  reverseLookup: true,
  protocol: raw.Protocol.ICMP,
  packetSize: 52,
  outStream: process.stdout
};

export class Traceroute {
  private readonly icmpSocket = raw.createSocket({
    protocol: raw.Protocol.ICMP
  });
  private readonly resolver = new Resolver();
  private readonly options: Options;
  private readonly subject = new EventEmitter();
  private port = 33433;
  private ttl = 1;
  private startTime?: [number, number];
  private probes = 0;
  private timeout?: NodeJS.Timeout;
  private previousIP?: string;
  private udpSocket?: dgram.Socket;
  private destinationHostname: string;

  constructor(
    private destinationIp: string,
    userOptions: Partial<Options> = {}
  ) {
    const maximumHops = userOptions.maximumHops || defaultOptions.maximumHops;

    this.options = {
      ...defaultOptions,
      ...Helpers.omit(userOptions),
      ...(maximumHops > 255 || maximumHops < 1
        ? { maximumHops: defaultOptions.maximumHops }
        : { maximumHops })
    };

    this.destinationHostname = this.destinationIp;

    this.icmpSocket.on('error', (e) => this.emitError(e));

    this.icmpSocket.on('message', async (buffer: Buffer, ip: string) => {
      const port = this.parseIdFromIcmpMessage(buffer);

      logger.debug(
        'Received ICMP %s bytes (message: %s) from %s:%s',
        buffer.length,
        buffer.toString('hex'),
        ip,
        port
      );

      if (port === this.port) {
        const hostName = await this.getHostName(ip);
        this.handleReply(ip, hostName);
      }
    });
  }

  public async execute(): Promise<ReturnType> {
    if (!isIP(this.destinationIp)) {
      try {
        this.destinationIp = (
          await this.resolver.resolve(this.destinationHostname, 'A')
        )[0];
      } catch (err) {
        logger.debug(
          'Cannot resolve the following hostname: %s. Error: %s',
          this.destinationHostname,
          err
        );
      }
    }

    process.stdout.write(
      `traceroute to ${this.destinationHostname} (${this.destinationIp}), ${this.options.maximumHops} hops max, ${this.options.packetSize} byte packets`
    );

    if (this.options.protocol === raw.Protocol.UDP) {
      this.udpSocket = dgram.createSocket('udp4');

      this.udpSocket.on('error', (e) => this.emitError(e));

      this.udpSocket.bind(() => this.sendPacket());
    } else {
      setImmediate(() => this.sendPacket());
    }

    const [reached]: ReturnType[] = await once(this.subject, Stop);

    this.abort();

    return reached;
  }

  private abort(): void {
    if (this.udpSocket) {
      this.udpSocket.close();
    }
    this.icmpSocket.close();
  }

  private async getHostName(ip: string): Promise<string | undefined> {
    if (!this.options.reverseLookup) {
      return;
    }

    try {
      const [hostname]: string[] = await this.resolver.reverse(ip);

      return hostname;
    } catch (err) {
      logger.debug(
        'Cannot reverse the following IP address: %s. Error: %s',
        ip,
        err
      );
    }
  }

  private sendPacket(): void {
    if (this.probes >= this.options.amountProbes) {
      this.probes = 0;
      this.ttl++;
    }

    this.probes++;

    const buffer = this.createPingRequest(
      0,
      0,
      ++this.port,
      this.options.packetSize
    );

    if (this.udpSocket) {
      try {
        this.udpSocket.setTTL(this.ttl);
      } catch (e) {
        this.emitError(e as Error);

        return;
      }
      this.udpSocket.send(
        buffer,
        0,
        buffer.length,
        this.port,
        this.destinationIp,
        this.afterSend.bind(this)
      );
    } else {
      this.icmpSocket.setOption(
        raw.SocketLevel.IPPROTO_IP,
        raw.SocketOption.IP_TTL,
        this.ttl
      );
      this.icmpSocket.send(
        buffer,
        0,
        buffer.length,
        this.destinationIp,
        this.afterSend.bind(this)
      );
    }
  }

  /**
   * For error type responses the sequence and ID cannot be
   * extracted, the data part contains the IP header from our request,
   * followed with at least 8 bytes from the echo request that generated the error.
   * In detail look up in https://en.wikipedia.org/wiki/Ping_(networking_utility)
   * and https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
   */
  private parseIdFromIcmpMessage(msg: Buffer): number | undefined {
    let offset = 20;

    const type = msg.readUInt8(offset);

    if (type === 3 || type === 4 || type === 5 || type === 11) {
      const icmpIPOffset = offset + 8;

      // IPv4 takes no less 20 bytes in an IP header
      if (
        msg.length - icmpIPOffset < 20 ||
        // eslint-disable-next-line no-bitwise
        (msg.readUInt8(icmpIPOffset) & 0xf0) !== 0x40
      ) {
        return;
      }

      // eslint-disable-next-line no-bitwise
      const icmpIPLength = (msg.readUInt8(icmpIPOffset) & 0x0f) * 4;

      // ICMP message too short
      if (msg.length - icmpIPOffset - icmpIPLength < 8) {
        return;
      }

      offset = icmpIPOffset + icmpIPLength;
    }

    return msg.readUInt16BE(offset + 6);
  }

  private afterSend(error: Error | null) {
    if (error) {
      this.emitError(error);

      return;
    }

    this.timeout = setTimeout(
      () => this.handleReply(),
      this.options.timeoutInMillis
    );
  }

  private handleReply(ip?: string, symbolicAddress?: string): void {
    this.clearTimeout();

    const formattedTTL = this.ttl.toFixed().padStart(3, ' ');

    if (ip) {
      const elapsedTime = `${(
        process.hrtime(this.startTime)[1] / 1000000
      ).toFixed(3)} ms`;

      if (ip === this.previousIP) {
        process.stdout.write(` ${elapsedTime} `);
      } else if (this.probes === 1) {
        process.stdout.write(
          `\n${formattedTTL}  ${
            symbolicAddress ? symbolicAddress : ip
          } (${ip})  ${elapsedTime} `
        );
      } else {
        process.stdout.write(
          `\n${Array(formattedTTL.length).fill(' ').join('')}  ${
            symbolicAddress ? symbolicAddress : ip
          } (${ip})  ${elapsedTime} `
        );
      }
    } else {
      process.stdout.write(this.probes === 1 ? `\n${formattedTTL}  * ` : `* `);
    }

    if (
      this.probes === this.options.amountProbes &&
      (ip === this.destinationIp || this.ttl >= this.options.maximumHops)
    ) {
      process.stdout.write('\n');
      this.subject.emit(Stop, {
        reached: ip === this.destinationIp
      });

      return;
    }

    this.previousIP = ip;

    setImmediate(() => this.sendPacket());
  }

  private createPingRequest(
    type: number,
    identifier: number,
    sequence: number,
    packetSize = 0
  ): Buffer {
    const header = [
      type || 0x08,
      0x00,
      0x00,
      0x00,
      this.secondByte(identifier),
      this.firstByte(identifier),
      this.secondByte(sequence),
      this.firstByte(sequence)
    ];
    const req = [...header, ...Array(packetSize).fill(0xff)];

    const buffer = Buffer.from(req);
    raw.writeChecksum(buffer, 2, raw.createChecksum(buffer));

    return buffer;
  }

  private firstByte(value: number): number {
    // eslint-disable-next-line no-bitwise
    return value & 0xff;
  }

  private secondByte(value: number): number {
    // eslint-disable-next-line no-bitwise
    return (value & 0xff00) >> 8;
  }

  private clearTimeout(): void {
    if (this.timeout) {
      clearTimeout(this.timeout);
    }
  }

  private emitError(error: Error): void {
    this.subject.emit('error', error);
  }
}
