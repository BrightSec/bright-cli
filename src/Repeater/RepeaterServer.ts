import { Protocol } from '../RequestExecutor';
import { NetworkTestType } from './NetworkTestType';

export interface RepeaterServerDeployedEvent {
  repeaterId: string;
}

export interface RepeaterServerRequestEvent {
  protocol: Protocol;
  url: string;
  method?: string;
  headers?: Record<string, string | string[]>;
  correlationIdRegex?: string;
  body?: string;
  encoding?: 'base64';
  maxContentSize?: number;
  timeout?: number;
  // Carried as a DTO field by bridges; read for the Sentry tag, never sent to the target.
  traceId?: string;
  entrypointId?: string;
  scanId?: string;
  discoveryId?: string;
}

export type RepeaterServerNetworkTestEvent =
  | {
      type: NetworkTestType.PING;
      input: string[];
    }
  | {
      type: NetworkTestType.TRACEROUTE;
      input: string;
    };

export type RepeaterServerNetworkTestResult =
  | {
      output: string;
    }
  | {
      error: string;
    };

export type RepeaterServerRequestResponse =
  | {
      protocol: Protocol;
      statusCode?: number;
      message?: string;
      errorCode?: string;
      headers?: Record<string, string | string[] | undefined>;
      body?: string;
      encoding?: 'base64';
      ttfb?: number;
    }
  | {
      protocol: Protocol;
      message?: string;
      errorCode?: string;
    };

export interface RepeaterServerReconnectionFailedEvent {
  error: Error;
}

export interface RepeaterServerReconnectionAttemptedEvent {
  attempt: number;
}

export enum RepeaterErrorCodes {
  REPEATER_NOT_PERMITTED = 'repeater_not_permitted',
  REPEATER_ALREADY_STARTED = 'repeater_already_started',
  REPEATER_DEACTIVATED = 'repeater_deactivated',
  REPEATER_UNAUTHORIZED = 'repeater_unauthorized',
  REPEATER_NO_LONGER_SUPPORTED = 'repeater_no_longer_supported',
  UNKNOWN_ERROR = 'unknown_error',
  UNEXPECTED_ERROR = 'unexpected_error'
}

export interface RepeaterServerErrorEvent {
  message: string;
  code: RepeaterErrorCodes;
  transaction?: string;
  remediation?: string;
}

export interface RepeaterUpgradeAvailableEvent {
  version: string;
}

export interface RepeaterLimitsEvent {
  maxBodySize: number;
}

export interface RepeaterServerScriptsUpdatedEvent {
  script: string | Record<string, string>;
}

export interface DeployCommandOptions {
  repeaterId?: string;
}

export interface DeploymentRuntime {
  version: string;
  scriptsLoaded: boolean;
  localScriptsLoaded: boolean;
  ci?: string;
  os?: string;
  arch?: string;
  docker?: boolean;
  distribution?: string;
  nodeVersion?: string;
}

export const enum RepeaterServerEvents {
  DEPLOYED = 'deployed',
  DEPLOY = 'deploy',
  CONNECTED = 'connected',
  DISCONNECTED = 'disconnected',
  REQUEST = 'request',
  TEST_NETWORK = 'test_network',
  UPDATE_AVAILABLE = 'update_available',
  LIMITS = 'limits',
  SCRIPTS_UPDATED = 'scripts_updated',
  RECONNECTION_FAILED = 'reconnection_failed',
  RECONNECT_ATTEMPT = 'reconnect_attempt',
  RECONNECTION_SUCCEEDED = 'reconnection_succeeded',
  ERROR = 'error',
  PING = 'ping'
}

export interface RepeaterServerEventsMap {
  [RepeaterServerEvents.DEPLOY]: [DeployCommandOptions, DeploymentRuntime?];
  [RepeaterServerEvents.DEPLOYED]: RepeaterServerDeployedEvent;
  [RepeaterServerEvents.CONNECTED]: void;
  [RepeaterServerEvents.DISCONNECTED]: void;
  [RepeaterServerEvents.REQUEST]: RepeaterServerRequestEvent;
  [RepeaterServerEvents.TEST_NETWORK]: RepeaterServerNetworkTestEvent;
  [RepeaterServerEvents.UPDATE_AVAILABLE]: RepeaterUpgradeAvailableEvent;
  [RepeaterServerEvents.LIMITS]: RepeaterLimitsEvent;
  [RepeaterServerEvents.SCRIPTS_UPDATED]: RepeaterServerScriptsUpdatedEvent;
  [RepeaterServerEvents.RECONNECTION_FAILED]: RepeaterServerReconnectionFailedEvent;
  [RepeaterServerEvents.RECONNECT_ATTEMPT]: RepeaterServerReconnectionAttemptedEvent;
  [RepeaterServerEvents.RECONNECTION_SUCCEEDED]: void;
  [RepeaterServerEvents.ERROR]: RepeaterServerErrorEvent;
  [RepeaterServerEvents.PING]: void;
}

export type RepeaterServerEventHandler<
  K extends keyof RepeaterServerEventsMap
> = (
  ...args: RepeaterServerEventsMap[K] extends (infer U)[]
    ? U[]
    : [RepeaterServerEventsMap[K]]
) => unknown;

export interface RepeaterServer {
  disconnect(): void;

  connect(hostname: string): Promise<void>;

  deploy(
    options: DeployCommandOptions,
    runtime?: DeploymentRuntime
  ): Promise<RepeaterServerDeployedEvent>;

  on<K extends keyof RepeaterServerEventsMap>(
    event: K,
    handler: RepeaterServerEventHandler<K>
  ): void;

  off<K extends keyof RepeaterServerEventsMap>(
    event: K,
    handler?: RepeaterServerEventHandler<K>
  ): void;
}

export const RepeaterServer: unique symbol = Symbol('RepeaterServer');
