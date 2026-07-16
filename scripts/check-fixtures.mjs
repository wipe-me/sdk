import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const fixture = JSON.parse(await readFile(resolve(root, "fixtures/v1/message-only.json"), "utf8"));
if (fixture.protocol_version !== 1) throw new Error("fixture protocol version changed");
if (!/^[1-9A-HJ-NP-Za-km-z]{12}$/.test(fixture.message_id)) throw new Error("invalid fixture message ID");
if (!/^[1-9A-HJ-NP-Za-km-z]{16}$/.test(fixture.secret)) throw new Error("invalid fixture secret");
const envelope = Buffer.from(fixture.expected_envelope_base64, "base64");
if (envelope.subarray(0, 8).toString("hex") !== "574950454d450001") throw new Error("invalid envelope magic/version");
if (envelope.length < 66 || envelope.at(-1) !== 0) throw new Error("invalid envelope framing");
console.log(`validated ${fixture.name} (${envelope.length} bytes)`);
