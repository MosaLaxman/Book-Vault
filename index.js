import express from "express";
import pg from "pg";
import dotenv from "dotenv";
import axios from "axios";
import crypto from "crypto";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const PASSWORD_ITERATIONS = 120000;

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

const db = new pg.Client({
  connectionString: process.env.DATABASE_URL || undefined,
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

function parseCookies(cookieHeader = "") {
  return cookieHeader
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const separatorIndex = part.indexOf("=");
      if (separatorIndex === -1) {
        return acc;
      }
      const key = part.slice(0, separatorIndex);
      const value = decodeURIComponent(part.slice(separatorIndex + 1));
      acc[key] = value;
      return acc;
    }, {});
}

function buildPasswordHash(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto
    .pbkdf2Sync(password, salt, PASSWORD_ITERATIONS, 64, "sha512")
    .toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  const [salt, originalHash] = (storedHash || "").split(":");
  if (!salt || !originalHash) {
    return false;
  }

  const computed = crypto
    .pbkdf2Sync(password, salt, PASSWORD_ITERATIONS, 64, "sha512")
    .toString("hex");
  const originalBuffer = Buffer.from(originalHash, "hex");
  const computedBuffer = Buffer.from(computed, "hex");
  if (originalBuffer.length !== computedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(originalBuffer, computedBuffer);
}

function setSessionCookie(res, sessionId) {
  const secure = process.env.NODE_ENV === "production";
  const maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000);
  const cookie = [
    `sid=${encodeURIComponent(sessionId)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`,
  ];

  if (secure) {
    cookie.push("Secure");
  }

  res.setHeader("Set-Cookie", cookie.join("; "));
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", "sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
}

async function createSession(userId) {
  const sessionId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await db.query(
    `INSERT INTO sessions (id, user_id, expires_at)
     VALUES ($1, $2, $3)`,
    [sessionId, userId, expiresAt]
  );
  return sessionId;
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.redirect("/signin");
  }
  next();
}

app.use((req, res, next) => {
  req.cookies = parseCookies(req.headers.cookie || "");
  next();
});

app.use(async (req, res, next) => {
  try {
    const sessionId = req.cookies.sid;
    req.user = null;
    res.locals.currentUser = null;

    if (!sessionId) {
      return next();
    }

    const result = await db.query(
      `SELECT users.id, users.email
       FROM sessions
       JOIN users ON sessions.user_id = users.id
       WHERE sessions.id = $1 AND sessions.expires_at > NOW()`,
      [sessionId]
    );

    if (result.rows.length === 0) {
      clearSessionCookie(res);
      return next();
    }

    req.user = result.rows[0];
    res.locals.currentUser = result.rows[0];

    await db.query(
      `UPDATE sessions
       SET expires_at = $2
       WHERE id = $1`,
      [sessionId, new Date(Date.now() + SESSION_TTL_MS)]
    );

    next();
  } catch (err) {
    next(err);
  }
});

app.get("/signup", (req, res) => {
  if (req.user) {
    return res.redirect("/");
  }
  res.render("signUp.ejs", { error: null, email: "" });
});

app.post("/signup", async (req, res, next) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = req.body.password || "";
    const confirmPassword = req.body.confirm_password || "";

    if (!email || !password) {
      return res.status(400).render("signUp.ejs", {
        error: "Email and password are required.",
        email,
      });
    }

    if (password.length < 8) {
      return res.status(400).render("signUp.ejs", {
        error: "Password must be at least 8 characters.",
        email,
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).render("signUp.ejs", {
        error: "Passwords do not match.",
        email,
      });
    }

    const existing = await db.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rows.length > 0) {
      return res.status(400).render("signUp.ejs", {
        error: "An account with this email already exists.",
        email,
      });
    }

    const passwordHash = buildPasswordHash(password);
    const inserted = await db.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id`,
      [email, passwordHash]
    );

    const sessionId = await createSession(inserted.rows[0].id);
    setSessionCookie(res, sessionId);
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

app.get("/signin", (req, res) => {
  if (req.user) {
    return res.redirect("/");
  }
  res.render("signIn.ejs", { error: null, email: "" });
});

app.post("/signin", async (req, res, next) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = req.body.password || "";

    const result = await db.query(
      `SELECT id, email, password_hash
       FROM users
       WHERE email = $1`,
      [email]
    );

    if (result.rows.length === 0 || !verifyPassword(password, result.rows[0].password_hash)) {
      return res.status(401).render("signIn.ejs", {
        error: "Invalid email or password.",
        email,
      });
    }

    const sessionId = await createSession(result.rows[0].id);
    setSessionCookie(res, sessionId);
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

app.post("/logout", async (req, res, next) => {
  try {
    const sessionId = req.cookies.sid;
    if (sessionId) {
      await db.query("DELETE FROM sessions WHERE id = $1", [sessionId]);
    }
    clearSessionCookie(res);
    res.redirect("/signin");
  } catch (err) {
    next(err);
  }
});

app.get("/", requireAuth, async (req, res, next) => {
  try {
    const sortBy = req.query.sort || "id";
    const search = req.query.search || "";
    const order = (req.query.order || "desc").toLowerCase() === "asc" ? "asc" : "desc";
    const minRating = Number(req.query.min_rating) || 0;

    const allowed = ["id", "date_read", "rating", "title"];
    const column = allowed.includes(sortBy) ? sortBy : "id";

    let query = `SELECT * FROM books WHERE user_id = $1`;
    const values = [req.user.id];

    if (search) {
      query += ` AND (LOWER(title) LIKE $${values.length + 1} OR LOWER(author) LIKE $${values.length + 1})`;
      values.push(`%${search.toLowerCase()}%`);
    }

    if (minRating > 0) {
      query += ` AND rating >= $${values.length + 1}`;
      values.push(minRating);
    }

    query += ` ORDER BY ${column} ${order.toUpperCase()}`;

    const result = await db.query(query, values);
    const books = result.rows;

    const totalBooks = books.length;
    const avgRating =
      totalBooks > 0
        ? (books.reduce((sum, book) => sum + Number(book.rating || 0), 0) / totalBooks).toFixed(1)
        : null;
    const latestRead =
      totalBooks > 0
        ? books
            .filter((book) => book.date_read)
            .sort((a, b) => new Date(b.date_read) - new Date(a.date_read))[0]?.date_read || null
        : null;

    res.render("front.ejs", {
      books,
      message: books.length === 0 ? "No books found." : null,
      currentSort: sortBy,
      currentSearch: search,
      currentOrder: order,
      currentMinRating: minRating,
      stats: {
        totalBooks,
        avgRating,
        latestRead,
      },
    });
  } catch (err) {
    next(err);
  }
});

app.get("/books/new", requireAuth, (req, res) => {
  res.render("newBook.ejs");
});

app.get("/api/book/:isbn", requireAuth, async (req, res) => {
  try {
    const isbn = req.params.isbn;

    const response = await axios.get(
      `https://openlibrary.org/api/books?bibkeys=ISBN:${isbn}&format=json&jscmd=data`
    );

    const data = response.data[`ISBN:${isbn}`];

    if (!data) {
      return res.json({ success: false });
    }

    res.json({
      success: true,
      title: data.title || "",
      author: data.authors ? data.authors[0].name : "",
    });
  } catch (err) {
    console.error(err);
    res.json({ success: false });
  }
});

app.post("/books/add", requireAuth, async (req, res, next) => {
  try {
    const { title, author, rating, review, date_read, isbn } = req.body;

    const coverUrl = isbn
      ? `https://covers.openlibrary.org/b/isbn/${isbn}-L.jpg`
      : "https://via.placeholder.com/300x400?text=No+Cover";

    await db.query(
      `INSERT INTO books (title, author, rating, review, date_read, cover_url, user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [title, author, rating, review, date_read, coverUrl, req.user.id]
    );

    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

app.post("/books/delete", requireAuth, async (req, res, next) => {
  try {
    await db.query("DELETE FROM books WHERE id = $1 AND user_id = $2", [
      req.body.deleteItemId,
      req.user.id,
    ]);
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

app.get("/books/:id/edit", requireAuth, async (req, res, next) => {
  try {
    const result = await db.query("SELECT * FROM books WHERE id = $1 AND user_id = $2", [
      req.params.id,
      req.user.id,
    ]);
    if (result.rows.length === 0) {
      return res.status(404).send("Book not found.");
    }

    res.render("editBook.ejs", { book: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

app.post("/books/edit/update", requireAuth, async (req, res, next) => {
  try {
    const { bookId, title, author, rating, review, date_read } = req.body;
    await db.query(
      `UPDATE books
       SET title = $1, author = $2, rating = $3, review = $4, date_read = $5
       WHERE id = $6 AND user_id = $7`,
      [title, author, rating, review, date_read, bookId, req.user.id]
    );
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something went wrong.");
});

async function ensureSchema() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id UUID PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await db.query(`
    ALTER TABLE books
    ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE CASCADE
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_books_user_id ON books(user_id)
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)
  `);
}

async function startServer() {
  try {
    await db.connect();
    console.log("Connected to PostgreSQL");
    await ensureSchema();
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (err) {
    console.error("Startup error:", err);
    process.exit(1);
  }
}

startServer();
