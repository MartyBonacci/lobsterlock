const DEBUG = !!process.env.DEBUG;

function formatData(data?: Record<string, unknown>): string {
  if (!data || Object.keys(data).length === 0) return '';
  return ' ' + JSON.stringify(data);
}

export const logger = {
  info(msg: string, data?: Record<string, unknown>): void {
    console.log(`[${new Date().toISOString()}] [INFO] ${msg}${formatData(data)}`);
  },

  warn(msg: string, data?: Record<string, unknown>): void {
    console.error(`[${new Date().toISOString()}] [WARN] ${msg}${formatData(data)}`);
  },

  error(msg: string, data?: Record<string, unknown>): void {
    console.error(`[${new Date().toISOString()}] [ERROR] ${msg}${formatData(data)}`);
  },

  debug(msg: string, data?: Record<string, unknown>): void {
    if (DEBUG) {
      console.log(`[${new Date().toISOString()}] [DEBUG] ${msg}${formatData(data)}`);
    }
  },
};
