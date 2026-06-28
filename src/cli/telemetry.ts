import { randomUUID } from "node:crypto";
import { appendFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

import type { OperationTelemetryEvent, OperationTelemetrySink } from "../kernel/operationTelemetry.js";

export interface CliTrace {
  readonly command: string;
  readonly runId: string;
  readonly traceId: string;
  readonly correlationId: string;
  readonly rootSpanId: string;
  readonly startedAt: string;
  readonly startedMs: number;
}

export function createCliTrace(command: string): CliTrace {
  const traceId = process.env.CUSTOMS_TRACE_ID ?? randomUUID();
  return {
    command,
    runId: randomUUID(),
    traceId,
    correlationId: process.env.CUSTOMS_CORRELATION_ID ?? traceId,
    rootSpanId: randomUUID(),
    startedAt: new Date().toISOString(),
    startedMs: performance.now()
  };
}

export function elapsedMs(trace: CliTrace): number {
  return Math.round((performance.now() - trace.startedMs) * 1000) / 1000;
}

export function errorCode(error: unknown): string {
  if (error instanceof Error && error.name.length > 0) {
    return error.name;
  }
  return "Error";
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export type TelemetryStatus = "started" | "ok" | "allowed" | "blocked" | "failed" | "error";

export interface CliTelemetryFields {
  readonly operation: string;
  readonly status: TelemetryStatus;
  readonly durationMs?: number | undefined;
  readonly errorCode?: string | undefined;
  readonly [key: string]: unknown;
}

export function emitCliEvent(trace: CliTrace, event: string, fields: CliTelemetryFields): void {
  const payload = {
    schema: "customs.cli_event.v1",
    event,
    command: trace.command,
    runId: trace.runId,
    traceId: trace.traceId,
    correlationId: trace.correlationId,
    rootSpanId: trace.rootSpanId,
    spanId: randomUUID(),
    parentSpanId: trace.rootSpanId,
    startedAt: trace.startedAt,
    timestamp: new Date().toISOString(),
    ...fields
  };
  const line = JSON.stringify(payload);
  const file = process.env.CUSTOMS_TELEMETRY_FILE;
  const stderrEnabled = process.env.CUSTOMS_TELEMETRY_STDERR !== "0" || file === undefined;
  if (stderrEnabled) {
    console.error(line);
  }
  if (file !== undefined) {
    appendFileSync(file, `${line}\n`, "utf8");
  }
}

export function createCliTelemetrySink(trace: CliTrace): OperationTelemetrySink {
  return (event: OperationTelemetryEvent) => {
    const { schema: _schema, operation, status, ...fields } = event;
    emitCliEvent(trace, `customs_${operation.replaceAll(".", "_")}`, {
      ...fields,
      operation,
      status
    });
  };
}
