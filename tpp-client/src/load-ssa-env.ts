import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export function loadSsaEnv(envPath: string): Record<string, string> {
  const content = readFileSync(envPath, "utf8");
  const vars: Record<string, string> = {};

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const eq = line.indexOf("=");
    if (eq <= 0) {
      continue;
    }

    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    vars[key] = value;
  }

  return vars;
}

export function loadOptionalDotEnv(tppClientRoot: string): void {
  const dotEnvPath = resolve(tppClientRoot, ".env");
  try {
    const vars = loadSsaEnv(dotEnvPath);
    for (const [key, value] of Object.entries(vars)) {
      if (process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch {
    // .env opcional
  }
}
