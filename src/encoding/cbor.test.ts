import { test, expect } from "vitest";
import { encodeCbor } from "./cbor.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

test("shortest form for every integer width, including 2^32 and above", () => {
  const rows: Array<[number, string]> = [
    [0, "00"],
    [23, "17"],
    [24, "1818"],
    [255, "18ff"],
    [256, "190100"],
    [65535, "19ffff"],
    [65536, "1a00010000"],
    [2 ** 31 - 1, "1a7fffffff"],
    [2 ** 32 - 1, "1affffffff"],
    [2 ** 32, "1b0000000100000000"],
    [2 ** 53 - 1, "1b001fffffffffffff"],
  ];
  for (const [n, want] of rows) expect(hex(encodeCbor(n)), String(n)).toBe(want);
});

test("byte strings are plain (no tag 64), text strings and null as RFC 8949 Appendix A", () => {
  expect(hex(encodeCbor(new Uint8Array([1, 2, 3, 4])))).toBe("4401020304");
  expect(hex(encodeCbor(Buffer.from([1, 2, 3, 4])))).toBe("4401020304");
  expect(hex(encodeCbor(new Uint8Array(0)))).toBe("40");
  expect(hex(encodeCbor("IETF"))).toBe("6449455446");
  expect(hex(encodeCbor("ü"))).toBe("62c3bc");
  expect(hex(encodeCbor("a".repeat(24)))).toBe(`7818${"61".repeat(24)}`);
  expect(hex(encodeCbor(null))).toBe("f6");
  expect(hex(encodeCbor([1, [2, 3], [4, 5]]))).toBe("8301820203820405");
});

test("refuses values outside the protocol's types", () => {
  for (const bad of [-1, 1.5, 2 ** 53, true, { a: 1 }, undefined]) {
    expect(() => encodeCbor(bad as never), String(bad)).toThrow(TypeError);
  }
});
