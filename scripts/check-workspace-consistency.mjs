import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { resolve } from "node:path";

const sdkRoot = resolve(import.meta.dirname, "..");
const workspace = resolve(process.argv[2] ?? sdkRoot, process.argv[2] ? "." : "..");
const fixture = JSON.parse(await readFile(resolve(sdkRoot, "fixtures/v1/message-only.json"), "utf8"));
const required = (text, needle, source) => {
  if (!text.includes(needle)) throw new Error(`${source} is inconsistent: missing ${JSON.stringify(needle)}`);
};

const cliProtocolPath = resolve(workspace, "cli/docs/protocol-v1.md");
const openAPIPath = resolve(workspace, "openapi/wipe-api.v1.yaml");
for (const path of [cliProtocolPath, openAPIPath]) await access(path, constants.R_OK);

const cliProtocol = await readFile(cliProtocolPath, "utf8");
required(cliProtocol, fixture.expected_envelope_base64, "CLI protocol vector");
required(cliProtocol, "64 MiB, 3 iterations, parallelism 1", "CLI production KDF");
for (const label of [
  "wipe.me/envelope/v1/encryption",
  "wipe.me/envelope/v1/deletion",
  "wipe.me/envelope/v1/manifest",
  "wipe.me/envelope/v1/attachment/",
]) required(cliProtocol, label, "CLI key schedule");

const openAPI = await readFile(openAPIPath, "utf8");
required(openAPI, "pattern: '^[1-9A-HJ-NP-Za-km-z]{12}$'", "OpenAPI message ID");
required(openAPI, "name: X-Wipe-Deletion-Key", "OpenAPI deletion capability");
required(openAPI, "name: X-Wipe-Cipher-Version", "OpenAPI cipher version");
required(openAPI, "const: 1", "OpenAPI protocol version");
required(openAPI, "maxLength: 3145728", "OpenAPI free message size");
required(openAPI, "no more than 14 days away", "OpenAPI free expiry");
required(openAPI, "pattern: '^[a-z][a-z0-9._-]{0,31}$'", "OpenAPI client identifier");
if (openAPI.includes("name: X-Wipe-On-Read")) throw new Error("OpenAPI still exposes X-Wipe-On-Read");
for (const code of ["message_too_large", "message_claimed", "internal_error", "authentication_required", "replay_detected"]) {
  required(openAPI, `- ${code}`, "OpenAPI error vocabulary");
}

console.log("CLI protocol vector/key schedule and backend OpenAPI constants are consistent with SDK v1");
