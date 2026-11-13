import { Logger, LogLevel } from '../Logger';
import { mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import os from 'os';

describe('Logger', () => {
  let logger: Logger;
  let stdoutSpy: jest.SpyInstance;
  let stderrSpy: jest.SpyInstance;
  let mockLogFile: { write: jest.Mock; end: jest.Mock };
  let tempDir: string;

  beforeEach(() => {
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation();
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation();
    tempDir = join(
      os.tmpdir(),
      'logger-test-' + Math.random().toString(36).substring(7)
    );
    mkdirSync(tempDir, { recursive: true });

    mockLogFile = {
      write: jest.fn(),
      end: jest.fn()
    };
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
    rmSync(tempDir, { recursive: true, force: true });
  });

  describe('constructor', () => {
    it('should initialize with default values', () => {
      logger = new Logger();
      expect(logger.logLevel).toBe(LogLevel.NOTICE);
      expect(logger.logFile).toBeUndefined();
    });

    it('should initialize with custom log level', () => {
      logger = new Logger(LogLevel.ERROR);
      expect(logger.logLevel).toBe(LogLevel.ERROR);
    });

    it('should initialize with custom log file', () => {
      const logPath = join(tempDir, 'test.log');
      logger = new Logger(LogLevel.NOTICE, logPath);
      expect(logger.logFile).toBe(logPath);
    });
  });

  describe('logging methods', () => {
    beforeEach(() => {
      logger = new Logger(LogLevel.TRACE);
    });

    it('should log error messages', () => {
      logger.error('test error');
      expect(stderrSpy).toHaveBeenCalled();

      // When logging to file
      logger = new Logger(LogLevel.TRACE);
      (logger as any)._logFile = mockLogFile;
      logger.error('test error');
      expect(stderrSpy).toHaveBeenCalledTimes(1); // No additional stderr calls
      expect(mockLogFile.write).toHaveBeenCalled();
    });

    it('should log error with Error object', () => {
      const error = new Error('test error');

      // When logging to file
      logger = new Logger(LogLevel.TRACE);
      (logger as any)._logFile = mockLogFile;
      logger.error(error);
      expect(stderrSpy).not.toHaveBeenCalled();
      expect(mockLogFile.write).toHaveBeenCalled();
      const logCall = (mockLogFile.write as jest.Mock).mock.calls[0][0];
      expect(logCall).toContain('test error');
      expect(logCall).toContain(error.stack);

      // When not logging to file
      logger = new Logger(LogLevel.TRACE);
      logger.error(error);
      expect(stderrSpy).toHaveBeenCalled();
    });

    it('should log warning messages', () => {
      // When logging to file
      logger = new Logger(LogLevel.TRACE);
      (logger as any)._logFile = mockLogFile;
      logger.warn('test warning');
      expect(stdoutSpy).not.toHaveBeenCalled();
      expect(mockLogFile.write).toHaveBeenCalled();

      // When not logging to file
      logger = new Logger(LogLevel.TRACE);
      logger.warn('test warning');
      expect(stdoutSpy).toHaveBeenCalled();
    });

    it('should log notice messages', () => {
      // When logging to file
      logger = new Logger(LogLevel.TRACE);
      (logger as any)._logFile = mockLogFile;
      logger.log('test notice');
      expect(stdoutSpy).not.toHaveBeenCalled();
      expect(mockLogFile.write).toHaveBeenCalled();

      // When not logging to file
      logger = new Logger(LogLevel.TRACE);
      logger.log('test notice');
      expect(stdoutSpy).toHaveBeenCalled();
    });

    it('should log debug messages', () => {
      // When logging to file
      logger = new Logger(LogLevel.TRACE);
      (logger as any)._logFile = mockLogFile;
      logger.debug('test debug');
      expect(stdoutSpy).not.toHaveBeenCalled();
      expect(mockLogFile.write).toHaveBeenCalled();

      // When not logging to file
      logger = new Logger(LogLevel.TRACE);
      logger.debug('test debug');
      expect(stdoutSpy).toHaveBeenCalled();
    });

    it('should log trace messages', () => {
      // When logging to file
      logger = new Logger(LogLevel.TRACE);
      (logger as any)._logFile = mockLogFile;
      logger.trace('test trace');
      expect(stdoutSpy).not.toHaveBeenCalled();
      expect(mockLogFile.write).toHaveBeenCalled();

      // When not logging to file
      logger = new Logger(LogLevel.TRACE);
      logger.trace('test trace');
      expect(stdoutSpy).toHaveBeenCalled();
    });

    it('should not log when level is below threshold', () => {
      logger.logLevel = LogLevel.ERROR;
      logger.warn('test warning');
      expect(stdoutSpy).not.toHaveBeenCalled();
      expect(mockLogFile.write).not.toHaveBeenCalled();
    });

    it('should format messages with arguments', () => {
      logger = new Logger(LogLevel.TRACE);
      (logger as any)._logFile = mockLogFile;
      logger.log('test %s %d', 'string', 123);
      const logCall = (mockLogFile.write as jest.Mock).mock.calls[0][0];
      expect(logCall).toContain('test string 123');
    });
  });

  describe('log file handling', () => {
    it('should create log directory if it does not exist', () => {
      const logPath = join(tempDir, 'nested', 'test.log');
      logger = new Logger(LogLevel.NOTICE, logPath);
      expect(logger.logFile).toBe(logPath);
    });

    it('should close previous log file when setting new one', () => {
      logger = new Logger();
      (logger as any)._logFile = mockLogFile;

      const logPath = join(tempDir, 'test.log');
      logger.logFile = logPath;

      expect(mockLogFile.end).toHaveBeenCalled();
    });

    it('should handle write errors gracefully', () => {
      logger = new Logger();
      (logger as any)._logFile = {
        write: () => {
          throw new Error('Write error');
        }
      };

      expect(() => {
        logger.log('test message');
      }).not.toThrow();
    });
  });

  describe('pauseTerminalOutput', () => {
    it('should hold stdout and stderr lines until the output is resumed', () => {
      // arrange
      logger = new Logger(LogLevel.VERBOSE);
      const order: string[] = [];
      stdoutSpy.mockImplementation((chunk: string) => order.push(chunk));
      stderrSpy.mockImplementation((chunk: string) => order.push(chunk));

      // act
      logger.pauseTerminalOutput();
      logger.debug('first');
      logger.error('second');
      const whilePaused = order.length;
      logger.resumeTerminalOutput();

      // assert
      expect(whilePaused).toBe(0);
      expect(order).toEqual([
        expect.stringContaining('first'),
        expect.stringContaining('second')
      ]);
    });

    it('should keep writing to the log file', () => {
      // arrange
      logger = new Logger();
      (logger as any)._logFile = mockLogFile;

      // act
      logger.pauseTerminalOutput();
      logger.log('test message');

      // assert
      expect(mockLogFile.write).toHaveBeenCalledWith(
        expect.stringContaining('test message')
      );
    });
  });

  describe('resumeTerminalOutput', () => {
    it('should release the held lines only when every pause is resumed', () => {
      // arrange
      logger = new Logger();
      logger.pauseTerminalOutput();
      logger.pauseTerminalOutput();
      logger.log('held');

      // act
      logger.resumeTerminalOutput();
      const afterFirst = stdoutSpy.mock.calls.length;
      logger.resumeTerminalOutput();

      // assert
      expect(afterFirst).toBe(0);
      expect(stdoutSpy).toHaveBeenCalledTimes(1);
    });

    it('should not hold later lines after an unmatched resume', () => {
      // arrange
      logger = new Logger();
      logger.resumeTerminalOutput();

      // act
      logger.log('not held');

      // assert
      expect(stdoutSpy).toHaveBeenCalledTimes(1);
    });
  });
});
