import { describe, it, expect } from "vitest";
import { assertBoundedString } from "./validation.js";
import { decodeStrictBase64 } from "../encoding/base64.js";

describe("validation helpers", () => {
  it("rejects overlong device ids", () => {
    const long = "a".repeat(300);
    expect(() => assertBoundedString("device_id", long, 256)).toThrow(/exceeds/);
  });

  it("strict base64 rejects whitespace/url-safe", () => {
    expect(() => decodeStrictBase64("bad", "abc_def")).toThrow();
    expect(() => decodeStrictBase64("bad", "abc def==")).toThrow();
    expect(() => decodeStrictBase64("bad", "short")).toThrow();
  });
});
