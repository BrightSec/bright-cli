import chalk from 'chalk';
import { createStream } from 'rotating-file-stream';
import { format } from 'node:util';
import { mkdirSync, existsSync } from 'fs';
import { dirname } from 'path';

export enum LogLevel {
  SILENT,
  ERROR,
  WARN,
  NOTICE,
  VERBOSE,
  TRACE
}

export interface LogFile {
  write(data: string): void;
  end?(): void;
}

export interface LogOptions {
  // Size in bytes, default 10MB
  maxSize?: string;
  // Maximum number of rotated files to keep, default 5
  maxFiles?: number;
  // Interval to rotate the file even if size is not exceeded
  // Examples: '1d', '12h', '7d'
  interval?: string;
  // Compression for rotated files ('gzip' or undefined)
  compress?: 'gzip';
}

export class Logger {
  private static instance: Logger;
  private readonly MAX_FORMATTED_LEVEL_LENGTH = Object.keys(LogLevel)
    .sort((a: string, b: string) => a.length - b.length)
    .slice(0)
    .pop().length;
  private _logLevel: LogLevel;
  private _logFile?: LogFile;
  private _logPath?: string;
  private _logOptions: LogOptions;
  private terminalPauses = 0;
  private heldTerminalWrites: (() => void)[] = [];

  constructor(
    logLevel: LogLevel = LogLevel.NOTICE,
    logFile?: string,
    options: LogOptions = {}
  ) {
    this._logLevel = logLevel;
    this._logOptions = {
      maxSize: options.maxSize || '10MB',
      maxFiles: options.maxFiles ?? 5,
      interval: options.interval || '1d',
      compress: options.compress ?? 'gzip'
    };
    if (logFile) {
      this.logFile = logFile;
    }
  }

  public static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }

    return Logger.instance;
  }

  public static configure(
    logLevel: LogLevel = LogLevel.NOTICE,
    logFile?: string,
    options: LogOptions = {}
  ): Logger {
    const instance = Logger.getInstance();
    instance._logLevel = logLevel;
    instance._logOptions = {
      maxSize: options.maxSize || '10MB',
      maxFiles: options.maxFiles ?? 5,
      interval: options.interval || '1d',
      compress: options.compress ?? 'gzip'
    };
    if (logFile) {
      instance.logFile = logFile;
    }

    return instance;
  }

  get logLevel(): LogLevel {
    return this._logLevel;
  }

  set logLevel(value: LogLevel) {
    this._logLevel = value;
  }

  get logFile(): string | undefined {
    return this._logPath;
  }

  set logFile(filePath: string | undefined) {
    if (this._logFile && 'end' in this._logFile) {
      this._logFile.end();
    }
    this._logFile = undefined;
    this._logPath = undefined;

    if (filePath) {
      const dir = dirname(filePath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }

      // Create a rotating write stream
      this._logFile = createStream(filePath, {
        size: this._logOptions.maxSize,
        interval: this._logOptions.interval,
        compress: this._logOptions.compress,
        maxFiles: this._logOptions.maxFiles,
        // Rotate file names with timestamp
        rotate: 1
      });
      this._logPath = filePath;
    }
  }

  /**
   * Holds console output until the matching resumeTerminalOutput(), so that
   * log lines do not land on a line the user is typing into. The log file is
   * still written immediately.
   */
  public pauseTerminalOutput(): void {
    this.terminalPauses++;
  }

  public resumeTerminalOutput(): void {
    if (this.terminalPauses === 0) {
      return;
    }

    this.terminalPauses--;

    if (this.terminalPauses === 0) {
      const held = this.heldTerminalWrites;
      this.heldTerminalWrites = [];
      held.forEach((write: () => void) => write());
    }
  }

  public error(error: Error, message?: string, ...args: any[]): void;
  public error(message: string, ...args: any[]): void;
  public error(
    errorOrMessage: Error | string,
    messageOrArg: any,
    ...args: any[]
  ): void {
    if (this.logLevel < LogLevel.ERROR) {
      return;
    }

    let message: string;

    if (typeof errorOrMessage === 'string') {
      if (arguments.length > 1) {
        args.unshift(messageOrArg);
      }
      message = errorOrMessage;
    } else {
      const error = errorOrMessage as Error;
      message = messageOrArg || error.message;
      if (error.stack) {
        args.push(`\n${error.stack}`);
      }
    }

    const formatted = this.formatMessage('ERROR', message, args);
    if (!this._logFile) {
      this.writeToStderr(chalk.red(formatted));
    }
    this.writeToFile(formatted);
  }

  public warn(message: string, ...args: any[]): void {
    if (this.logLevel < LogLevel.WARN) {
      return;
    }

    const formatted = this.formatMessage('WARN', message, args);
    if (!this._logFile) {
      this.writeToStdout(chalk.yellow(formatted));
    }
    this.writeToFile(formatted);
  }

  public log(message: string, ...args: any[]): void {
    if (this.logLevel < LogLevel.NOTICE) {
      return;
    }

    const formatted = this.formatMessage('NOTICE', message, args);
    if (!this._logFile) {
      this.writeToStdout(chalk.green(formatted));
    }
    this.writeToFile(formatted);
  }

  public debug(message: string, ...args: any[]): void {
    if (this.logLevel < LogLevel.VERBOSE) {
      return;
    }

    const formatted = this.formatMessage('VERBOSE', message, args);
    if (!this._logFile) {
      this.writeToStdout(chalk.cyan(formatted));
    }
    this.writeToFile(formatted);
  }

  public trace(message: string, ...args: any[]): void {
    if (this.logLevel < LogLevel.TRACE) {
      return;
    }

    const formatted = this.formatMessage('TRACE', message, args);
    if (!this._logFile) {
      this.writeToStdout(chalk.cyan(formatted));
    }
    this.writeToFile(formatted);
  }

  private formatMessage(level: string, message: string, args: any[]): string {
    const formattedMessage = format(message, ...args);
    const formattedLevel = level
      .toUpperCase()
      .padEnd(this.MAX_FORMATTED_LEVEL_LENGTH, ' ');

    return `${new Date().toISOString()} [${formattedLevel}] ${formattedMessage}`;
  }

  private writeToFile(message: string): void {
    if (this._logFile) {
      try {
        this._logFile.write(`${message}\n`);
      } catch (error) {
        // Silently handle write errors in tests
      }
    }
  }

  private writeToStdout(message: string): void {
    this.writeToTerminal(() => process.stdout.write(`${message}\n`));
  }

  private writeToStderr(message: string): void {
    this.writeToTerminal(() => process.stderr.write(`${message}\n`));
  }

  private writeToTerminal(write: () => void): void {
    if (this.terminalPauses) {
      this.heldTerminalWrites.push(write);
    } else {
      write();
    }
  }
}

export const logger: Logger = Logger.getInstance();
