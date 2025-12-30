import type { Timestamp } from "@bufbuild/protobuf/wkt";

export function timestampToJsDate(timestamp: Timestamp | undefined): Date {
  if (!timestamp) {
    return new Date(0);
  }
  const seconds = Number(timestamp.seconds || 0n);
  const nanos = Number(timestamp.nanos || 0);
  const ms = seconds * 1000 + nanos / 1_000_000;
  return new Date(ms);
}
