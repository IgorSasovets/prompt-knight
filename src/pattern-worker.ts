// Runs inside a worker_threads.Worker so the main thread can terminate() it if a
// custom/user-supplied pattern hangs — the only reliable way to abort a runaway
// synchronous RegExp.exec in Node (D8, TM-1, REQ-T1-05).
import { parentPort } from "worker_threads";

export interface WorkerRequest {
  id: number;
  source: string;
  flags: string;
  text: string;
}

export interface WorkerMatch {
  index: number;
  length: number;
  matchedText: string;
}

export interface WorkerResponse {
  id: number;
  matches?: WorkerMatch[];
  error?: string;
}

if (!parentPort) {
  throw new Error("pattern-worker.ts must be run as a worker_threads worker");
}

parentPort.on("message", (req: WorkerRequest) => {
  try {
    const flags = req.flags.includes("g") ? req.flags : `${req.flags}g`;
    const regex = new RegExp(req.source, flags);
    const matches: WorkerMatch[] = [];
    let match: RegExpExecArray | null;
    while ((match = regex.exec(req.text)) !== null) {
      matches.push({ index: match.index, length: match[0].length, matchedText: match[0] });
      if (match[0].length === 0) regex.lastIndex += 1;
    }
    const response: WorkerResponse = { id: req.id, matches };
    parentPort!.postMessage(response);
  } catch (err) {
    const response: WorkerResponse = { id: req.id, error: (err as Error).message };
    parentPort!.postMessage(response);
  }
});
