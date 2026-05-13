import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";
import * as schema from "./schema";

// Use Turso/Cloud URL if provided, otherwise fallback to local SQLite for dev
const dbUrl = process.env.DATABASE_URL || "file:local.db";
const authToken = process.env.DATABASE_AUTH_TOKEN || undefined;

export const client = createClient({ url: dbUrl, authToken });
export const db = drizzle(client, { schema });

export * from "./schema";
