/**
 * Wire format payload types for v1 protocol.
 * These represent the decrypted inner payload structures.
 * JSON-serializable for extensibility.
 */

/**
 * Text message payload (v1).
 * Minimal structure for text-based messages, designed to be extensible.
 */
export interface MessagePayloadV1 {
  /** Payload type discriminator */
  type: "text";
  /** Client-generated message UUID for deduplication and tracking */
  client_message_id: string;
  /** ISO 8601 timestamp of when the message was created by the sender */
  sent_at: string;
  /** Message body content */
  body: {
    /** Plain text message content */
    text: string;
  };
}

// Future payload types can be added here as discriminated unions:
// export type PayloadV1 = MessagePayloadV1 | FilePayloadV1 | ...
