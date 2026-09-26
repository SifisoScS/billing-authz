/**
 * Primary entry point for this module.
 * Calls execute() and exits cleanly.
 */
export function start(): void {
  console.log("📦 Module starting...");
  execute();
}

/**
 * Execute the module's primary workload.
 * Override or extend this function to add domain-specific behaviour.
 */
export function execute(): void {
  console.log("📦 Module executed");
}

/**
 * Validate that the given input is defined.
 * @param input - Any value to check.
 * @returns true when input is not undefined.
 */
export function validate(input: unknown): boolean {
  return input !== undefined;
}
