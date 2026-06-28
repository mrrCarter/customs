import { createPrivateKey, createPublicKey, generateKeyPairSync, type JsonWebKey } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { LocalReceiptIssuer } from "./receipts.js";

export interface IssuerKeyStoreOptions {
  readonly createIfMissing?: boolean | undefined;
}

function isEnoent(error: unknown): boolean {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}

export async function loadOrCreateLocalReceiptIssuer(privateJwkPath: string, options: IssuerKeyStoreOptions = {}): Promise<LocalReceiptIssuer> {
  try {
    const privateJwk = JSON.parse(await readFile(privateJwkPath, "utf8")) as JsonWebKey;
    const privateKey = createPrivateKey({ key: privateJwk, format: "jwk" });
    return new LocalReceiptIssuer({ privateKey, publicKey: createPublicKey(privateKey) });
  } catch (error) {
    if (!isEnoent(error)) {
      throw error;
    }
  }

  if (options.createIfMissing !== true) {
    throw new Error(`issuer private key not found at ${privateJwkPath}; bootstrap explicitly with --create-issuer-key`);
  }

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateJwk = privateKey.export({ format: "jwk" });
  await mkdir(dirname(privateJwkPath), { recursive: true });
  await writeFile(privateJwkPath, `${JSON.stringify(privateJwk, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return new LocalReceiptIssuer({ privateKey, publicKey });
}
