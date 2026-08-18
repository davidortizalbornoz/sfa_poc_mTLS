import { execFileSync } from "node:child_process";

import type { MtlsClientConfig } from "./types.js";

export interface CurlMtlsOptions {
  config: MtlsClientConfig;
  method: "GET" | "POST";
  url: string;
  headers?: Record<string, string>;
  body?: string;
  resolve?: string;
}

export function buildMtlsCurlCommand(options: CurlMtlsOptions): string {
  const { config, method, url, headers = {}, body, resolve } = options;
  const lines = [
    "curl -sS \\",
    `  --cert '${config.transportCert}' \\`,
    `  --key '${config.transportKey}' \\`,
    `  --cacert '${config.caCert}' \\`,
    `  --resolve '${resolve ?? config.resolveAs}' \\`,
    `  -X ${method} '${url}' \\`,
  ];

  for (const [name, value] of Object.entries(headers)) {
    lines.push(`  -H '${name}: ${value.replace(/'/g, "'\\''")}' \\`);
  }

  if (body !== undefined) {
    lines.push(`  -d '${body.replace(/'/g, "'\\''")}'`);
  } else {
    lines[lines.length - 1] = lines[lines.length - 1]!.replace(/ \\$/, "");
  }

  return lines.join("\n");
}

export function runMtlsCurl(options: CurlMtlsOptions): string {
  const { config, method, url, headers = {}, body, resolve } = options;
  const args = [
    "-sS",
    "--cert",
    config.transportCert,
    "--key",
    config.transportKey,
    "--cacert",
    config.caCert,
    "--resolve",
    resolve ?? config.resolveAs,
    "-X",
    method,
    url,
  ];

  for (const [name, value] of Object.entries(headers)) {
    args.push("-H", `${name}: ${value}`);
  }

  if (body !== undefined) {
    args.push("-d", body);
  }

  return execFileSync("curl", args, { encoding: "utf8" });
}
