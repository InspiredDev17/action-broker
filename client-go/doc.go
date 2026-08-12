// Package actionbroker implements the standard-library Go client for Action
// Broker's local Unix-socket protocol.
//
// Requests and responses are JSON framed by a four-byte big-endian length. The
// client verifies a private Unix endpoint owned by the configured, distinct
// broker service UID before sending authority, validates the typed protocol
// envelope, and never retries an action. If the
// complete request was delivered but no broker-confirmed response arrives,
// Execute returns OutcomeUnknownError; a caller must reconcile the request ID
// instead of assuming cancellation or retrying a consequential action.
//
// ApprovalToken is intentionally opaque. Approval issuance, canonical RFC 8785
// argument and target digests, and token signing belong to the Personal AI
// Platform's approval service, not this transport client.
package actionbroker
