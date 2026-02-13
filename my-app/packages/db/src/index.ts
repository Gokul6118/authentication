import pkg from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { todos } from "./schema";
import {user} from "./loginschema";
const { Pool } = pkg;


let pool: pkg.Pool | null = null;
let db: ReturnType<typeof drizzle> | null = null;



export function getDb() {
  if (db) return db;

  const DATABASE_URL = process.env.DATABASE_URL;

  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL is missing");
  }

  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
      rejectUnauthorized: false,
    },
  });

  db = drizzle(pool);

  return db;
}

export { todos, user };
