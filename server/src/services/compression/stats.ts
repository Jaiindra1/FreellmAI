import type { CompressionMode, CompressionRequestStats } from './types.js';
import { getWorkspaceScope } from '../../db/index.js';

interface EngineAggregate {
  applied: number;
  discarded: number;
  savedChars: number;
}

interface ModeAggregate {
  requests: number;
  savedChars: number;
}

interface CompressionAggregate {
  requests: number;
  compressedRequests: number;
  originalChars: number;
  compressedChars: number;
  totalDurationMs: number;
  engines: Map<string, EngineAggregate>;
  modes: Map<CompressionMode, ModeAggregate>;
}

const aggregates = new Map<string, CompressionAggregate>();

function aggregate(): CompressionAggregate {
  const scope = getWorkspaceScope();
  let current = aggregates.get(scope);
  if (!current) {
    current = {
      requests: 0,
      compressedRequests: 0,
      originalChars: 0,
      compressedChars: 0,
      totalDurationMs: 0,
      engines: new Map(),
      modes: new Map(),
    };
    aggregates.set(scope, current);
  }
  return current;
}

export function recordCompressionStats(mode: CompressionMode, stats: CompressionRequestStats): void {
  const current = aggregate();
  current.requests += 1;
  if (stats.compressedChars < stats.originalChars) current.compressedRequests += 1;
  current.originalChars += stats.originalChars;
  current.compressedChars += stats.compressedChars;
  current.totalDurationMs += stats.durationMs;
  const modeRow = current.modes.get(mode) ?? { requests: 0, savedChars: 0 };
  modeRow.requests += 1;
  modeRow.savedChars += stats.originalChars - stats.compressedChars;
  current.modes.set(mode, modeRow);
  for (const stage of stats.stages) {
    const row = current.engines.get(stage.engine) ?? { applied: 0, discarded: 0, savedChars: 0 };
    if (stage.applied) row.applied += 1;
    else if (stage.discarded && stage.discarded !== 'disabled' && stage.discarded !== 'unchanged') row.discarded += 1;
    row.savedChars += stage.savedChars;
    current.engines.set(stage.engine, row);
  }
}

export function getCompressionStats() {
  const current = aggregate();
  const savedChars = Math.max(0, current.originalChars - current.compressedChars);
  return {
    requests: current.requests,
    compressedRequests: current.compressedRequests,
    originalChars: current.originalChars,
    compressedChars: current.compressedChars,
    estSavedTokens: Math.floor(savedChars / 4),
    savingsPercent: current.originalChars > 0 ? Math.round((savedChars / current.originalChars) * 10_000) / 100 : 0,
    avgDurationMs: current.requests > 0 ? Math.round((current.totalDurationMs / current.requests) * 100) / 100 : 0,
    byMode: Object.fromEntries([...current.modes.entries()].map(([mode, row]) => [
      mode,
      { ...row, estSavedTokens: Math.floor(row.savedChars / 4) },
    ])),
    engines: Object.fromEntries([...current.engines.entries()].sort(([a], [b]) => a.localeCompare(b))),
  };
}

export function clearCompressionStats(): void {
  aggregates.delete(getWorkspaceScope());
}
