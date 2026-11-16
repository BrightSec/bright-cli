import { Request } from './Request';
import { Response } from './Response';
import { Protocol } from './Protocol';

export interface RequestExecutor {
  execute(script: Request): Promise<Response>;
  /**
   * Runs once before the Repeater connects to the cloud. May read input from
   * the terminal.
   */
  prepare?(): Promise<void>;
  protocol: Protocol;
}

export const RequestExecutor: unique symbol = Symbol('RequestExecutor');
