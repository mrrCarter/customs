import { performance } from "node:perf_hooks";

export type OperationTelemetryStatus = "started" | "ok" | "failed";

export interface OperationTelemetryEvent {
  readonly schema: "customs.operation_event.v1";
  readonly operation: string;
  readonly status: OperationTelemetryStatus;
  readonly durationMs?: number | undefined;
  readonly errorCode?: string | undefined;
  readonly errorMessage?: string | undefined;
  readonly reason?: string | undefined;
  readonly [key: string]: unknown;
}

export interface OperationTelemetryInput {
  readonly operation: string;
  readonly status: OperationTelemetryStatus;
  readonly durationMs?: number | undefined;
  readonly errorCode?: string | undefined;
  readonly errorMessage?: string | undefined;
  readonly reason?: string | undefined;
  readonly [key: string]: unknown;
}

export type OperationTelemetrySink = (event: OperationTelemetryEvent) => void;

export function operationStartedMs(): number {
  return performance.now();
}

export function operationDurationMs(startedMs: number): number {
  return Math.round((performance.now() - startedMs) * 1000) / 1000;
}

export function operationErrorCode(error: unknown): string {
  if (error instanceof Error && error.name.length > 0) {
    return error.name;
  }
  return "Error";
}

export function operationErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function emitOperationTelemetry(
  sink: OperationTelemetrySink | undefined,
  event: OperationTelemetryInput
): void {
  const payload: OperationTelemetryEvent = {
    schema: "customs.operation_event.v1",
    ...event
  };
  sink?.(payload);
}

export function measuredOperation<T>(
  sink: OperationTelemetrySink | undefined,
  operation: string,
  fields: Readonly<Record<string, unknown>>,
  fn: () => T
): T {
  const startedMs = operationStartedMs();
  emitOperationTelemetry(sink, {
    ...fields,
    operation,
    status: "started"
  });
  try {
    const result = fn();
    emitOperationTelemetry(sink, {
      ...fields,
      operation,
      status: "ok",
      durationMs: operationDurationMs(startedMs)
    });
    return result;
  } catch (error) {
    emitOperationTelemetry(sink, {
      ...fields,
      operation,
      status: "failed",
      durationMs: operationDurationMs(startedMs),
      errorCode: operationErrorCode(error),
      errorMessage: operationErrorMessage(error)
    });
    throw error;
  }
}

export async function measuredAsyncOperation<T>(
  sink: OperationTelemetrySink | undefined,
  operation: string,
  fields: Readonly<Record<string, unknown>>,
  fn: () => Promise<T>
): Promise<T> {
  const startedMs = operationStartedMs();
  emitOperationTelemetry(sink, {
    ...fields,
    operation,
    status: "started"
  });
  try {
    const result = await fn();
    emitOperationTelemetry(sink, {
      ...fields,
      operation,
      status: "ok",
      durationMs: operationDurationMs(startedMs)
    });
    return result;
  } catch (error) {
    emitOperationTelemetry(sink, {
      ...fields,
      operation,
      status: "failed",
      durationMs: operationDurationMs(startedMs),
      errorCode: operationErrorCode(error),
      errorMessage: operationErrorMessage(error)
    });
    throw error;
  }
}
