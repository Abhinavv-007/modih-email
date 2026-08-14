// Centralized Developer API quotas keep handlers and dashboard endpoints in sync.
export const DEVELOPER_API_LIMITS = Object.freeze({
  inboxCreatesPerHour: 100,
  monthlyInboxCreates: 25_000,
  monthlyMessageReads: 250_000,
});
