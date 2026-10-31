"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// Runs inside a worker_threads.Worker so the main thread can terminate() it if a
// custom/user-supplied pattern hangs — the only reliable way to abort a runaway
// synchronous RegExp.exec in Node (D8, TM-1, REQ-T1-05).
const worker_threads_1 = require("worker_threads");
if (!worker_threads_1.parentPort) {
    throw new Error("pattern-worker.ts must be run as a worker_threads worker");
}
worker_threads_1.parentPort.on("message", (req) => {
    try {
        const flags = req.flags.includes("g") ? req.flags : `${req.flags}g`;
        const regex = new RegExp(req.source, flags);
        const matches = [];
        let match;
        while ((match = regex.exec(req.text)) !== null) {
            matches.push({ index: match.index, length: match[0].length, matchedText: match[0] });
            if (match[0].length === 0)
                regex.lastIndex += 1;
        }
        const response = { id: req.id, matches };
        worker_threads_1.parentPort.postMessage(response);
    }
    catch (err) {
        const response = { id: req.id, error: err.message };
        worker_threads_1.parentPort.postMessage(response);
    }
});
