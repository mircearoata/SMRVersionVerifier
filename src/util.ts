import fs from 'fs';

export async function sleep(seconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}

export function formatError(e: Error | string): string {
  return typeof e === 'string' ? e : `${e.message}\nStack trace:${e.stack}`;
}

export function setIntervalImmediate(func: (...args: unknown[]) => unknown, interval: number): number | NodeJS.Timeout {
  func();
  return setInterval(func, interval);
}

export function ensureExists(folder: string): void {
  fs.mkdirSync(folder, { recursive: true });
}
