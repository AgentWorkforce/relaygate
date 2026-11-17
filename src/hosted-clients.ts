/**
 * The hosted MCP clients relay-control enrols agents for with a one-time hosted credential (`sh_ht_`): the connector
 * kind of the grant behind a hosted participant (docs/contract.md, "Hosted participants"). A leaf, so the policy
 * schema and the control identity share it without importing each other.
 */
export const HOSTED_CLIENTS = ["chatgpt", "grok-bot", "muse", "cursor-cloud", "mcp"] as const;
export type HostedClient = (typeof HOSTED_CLIENTS)[number];
export const isHostedClient = (v: unknown): v is HostedClient =>
  typeof v === "string" && (HOSTED_CLIENTS as readonly string[]).includes(v);
