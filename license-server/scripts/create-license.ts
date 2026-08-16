/**
 * Mint a new license key.
 *
 * Usage:
 *   npm run create-license -- <tier> <ownerEmail> [expiresAt ISO date]
 *
 * Example:
 *   npm run create-license -- pro alice@example.com
 *   npm run create-license -- enterprise bob@bigco.com 2027-01-01
 *
 * This is a manual admin tool, not a self-serve signup flow — until there's
 * real payment integration, this is how you issue a key after someone pays
 * you directly.
 */
import * as crypto from "crypto";
import { createLicense, Tier } from "../src/db";

function main() {
  const [, , tierArg, email, expiresAt] = process.argv;

  if (!tierArg || !email) {
    console.error("Usage: npm run create-license -- <free|pro|enterprise> <ownerEmail> [expiresAt]");
    process.exit(1);
  }

  const tier = tierArg as Tier;
  if (!["free", "pro", "enterprise"].includes(tier)) {
    console.error(`Invalid tier "${tierArg}". Must be one of: free, pro, enterprise`);
    process.exit(1);
  }

  const random = crypto.randomBytes(16).toString("hex");
  const key = `sk-ryzek-${tier}-${random}`;

  createLicense(key, {
    tier,
    ownerEmail: email,
    createdAt: new Date().toISOString(),
    status: "active",
    ...(expiresAt ? { expiresAt } : {}),
  });

  console.log(`\nLicense created:`);
  console.log(`  Key:    ${key}`);
  console.log(`  Tier:   ${tier}`);
  console.log(`  Owner:  ${email}`);
  if (expiresAt) console.log(`  Expires: ${expiresAt}`);
  console.log(`\nGive this key to the customer. They activate it with:`);
  console.log(`  ryzek license set ${key}`);
}

main();
