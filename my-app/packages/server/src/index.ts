import { Hono } from "hono";
import { logger } from "hono/logger";
import {
  setSignedCookie,
  deleteCookie,
  getSignedCookie,
} from "hono/cookie";

import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import { getDb, todos, user } from "@repo/db";
import { eq, and } from "drizzle-orm";

const db = getDb();

const JWT_SECRET = process.env.JWT_SECRET!;
const COOKIE_SECRET = process.env.COOKIE_SECRET!;

const app = new Hono().basePath("/api");

app.use("*", logger());


const authMiddleware = async (c: any, next: any) => {
  try {
    const token = await getSignedCookie(
      c,
      COOKIE_SECRET,
      "auth_token"
    );

    if (!token) {
      return c.json(
        { message: "Please login first" },
        401
      );
    }

    const decoded = jwt.verify(token, JWT_SECRET) as {
      userId: number;
    };

    c.set("userId", decoded.userId);

    await next();
  } catch (err) {
    return c.json(
      { message: "Invalid or expired token" },
      401
    );
  }
};


app.post("/signup", async (c) => {
  const { email, password } = await c.req.json();

  if (!email || !password) {
    return c.json(
      { message: "Missing fields" },
      400
    );
  }

  const exists = await db
    .select()
    .from(user)
    .where(eq(user.email, email));

  if (exists.length) {
    return c.json(
      { message: "User already exists" },
      400
    );
  }

  const hashed = await bcrypt.hash(password, 10);

  await db.insert(user).values({
    email,
    password: hashed,
  });

  return c.json({ message: "Signup success" });
});


app.post("/login", async (c) => {
  const { email, password } = await c.req.json();

  const result = await db
    .select()
    .from(user)
    .where(eq(user.email, email));

  if (!result.length) {
    return c.json(
      { message: "Invalid credentials" },
      401
    );
  }

  const u = result[0];


if (!u) {
  return c.json(
    { message: "Invalid credentials" },
    401
  );
}

const valid = await bcrypt.compare(
  password,
  u.password
);

  if (!valid) {
    return c.json(
      { message: "Invalid credentials" },
      401
    );
  }
  const token = jwt.sign(
    {
      userId: u.id,
      email: u.email,
    },
    JWT_SECRET,
    { expiresIn: "24h" }
  );

  await setSignedCookie(
    c,
    "auth_token",
    token,
    COOKIE_SECRET,
    {
      httpOnly: true,
      secure: false, 
      sameSite: "Lax",
      path: "/",
    }
  );

  return c.json({ success: true });
});


app.post("/logout", (c) => {
  deleteCookie(c, "auth_token", {
    path: "/",
  });

  return c.json({ message: "Logged out" });
});


app.get("/", authMiddleware, async (c) => {
  try {
    const userId = c.get("userId");

    const data = await db
      .select()
      .from(todos)
      .where(eq(todos.userId, userId));

    return c.json(data);
  } catch (error) {
    console.error(error);

    return c.json(
      { message: "Failed to fetch todos" },
      500
    );
  }
});

app.post("/", authMiddleware, async (c) => {
  try {
    const userId = c.get("userId");
    const body = await c.req.json();

    const [todo] = await db
      .insert(todos)
      .values({
        text: body.text,
        description: body.description,
        status: body.status,

        startAt: new Date(body.startAt),
        endAt: new Date(body.endAt),

    
        userId,
      })
      .returning();

    return c.json(
      { success: true, data: todo },
      201
    );
  } catch (error) {
    console.error(error);

    return c.json(
      { message: "Failed to create todo" },
      500
    );
  }
});


app.put("/:id", authMiddleware, async (c) => {
  try {
    const userId = c.get("userId");
    const id = Number(c.req.param("id"));

    const body = await c.req.json();

    const [todo] = await db
      .update(todos)
      .set({
        text: body.text,
        description: body.description,
        status: body.status,

        startAt: new Date(body.startAt),
        endAt: new Date(body.endAt),
      })
      .where(
        and(
          eq(todos.id, id),
          eq(todos.userId, userId)
        )
      )
      .returning();

    if (!todo) {
      return c.json(
        { message: "Todo not found" },
        404
      );
    }

    return c.json({
      success: true,
      data: todo,
    });
  } catch (error) {
    console.error(error);

    return c.json(
      { message: "Failed to update todo" },
      500
    );
  }
});

app.patch("/:id", authMiddleware, async (c) => {
  try {
    const userId = c.get("userId");
    const id = Number(c.req.param("id"));

    const body = await c.req.json();

    const updateData: any = {};

    if (body.text !== undefined)
      updateData.text = body.text;

    if (body.description !== undefined)
      updateData.description = body.description;

    if (body.status !== undefined)
      updateData.status = body.status;

    if (body.startAt !== undefined)
      updateData.startAt = new Date(body.startAt);

    if (body.endAt !== undefined)
      updateData.endAt = new Date(body.endAt);

    const [todo] = await db
      .update(todos)
      .set(updateData)
      .where(
        and(
          eq(todos.id, id),
          eq(todos.userId, userId)
        )
      )
      .returning();

    if (!todo) {
      return c.json(
        { message: "Todo not found" },
        404
      );
    }

    return c.json({
      success: true,
      data: todo,
    });
  } catch (error) {
    console.error(error);

    return c.json(
      { message: "Failed to patch todo" },
      500
    );
  }
});

app.delete("/:id", authMiddleware, async (c) => {
  try {
    const userId = c.get("userId");
    const id = Number(c.req.param("id"));

    const result = await db
      .delete(todos)
      .where(
        and(
          eq(todos.id, id),
          eq(todos.userId, userId)
        )
      );

    if (!result.rowCount) {
      return c.json(
        { message: "Todo not found" },
        404
      );
    }

    return c.json({
      success: true,
      message: "Todo deleted",
    });
  } catch (error) {
    console.error(error);

    return c.json(
      { message: "Failed to delete todo" },
      500
    );
  }
});

export { app };
