import { generateKeyPairSync } from "node:crypto";

const pair = generateKeyPairSync("ed25519");

/** Production uses the same standard DER encodings, stored as canonical base64 in environment/secret values. */
export const ASSERTION_PRIVATE_KEY = pair.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
export const ASSERTION_PUBLIC_KEY = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64");
