import { Cert } from './Request';

export interface WhitelistMimeType {
  type: string;
  allowTruncation?: boolean;
}

export interface KerberosOptions {
  enabled: boolean;
  domains?: string[];
  credentials?: string;
  delegation?: boolean;
}

export interface RequestExecutorOptions {
  timeout?: number;
  proxyUrl?: string;
  headers?: Record<string, string | string[]>;
  certs?: Cert[];
  whitelistMimes?: WhitelistMimeType[];
  maxBodySize?: number;
  maxContentLength?: number;
  reuseConnection?: boolean;
  proxyDomains?: string[];
  proxyDomainsBypass?: string[];
  kerberos?: KerberosOptions;
  proxyTargetAttribution?: boolean;
}

export const RequestExecutorOptions: unique symbol = Symbol(
  'RequestExecutorOptions'
);
