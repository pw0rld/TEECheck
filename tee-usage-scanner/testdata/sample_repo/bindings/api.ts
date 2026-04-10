export async function submitTx(payload: Uint8Array): Promise<void> {
  if (!payload.byteLength) {
    throw new Error("empty payload");
  }

  await invokeNative("submitTx", payload);
}
