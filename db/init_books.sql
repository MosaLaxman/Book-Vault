CREATE TABLE IF NOT EXISTS books (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  author TEXT NOT NULL,
  rating INTEGER NOT NULL,
  review TEXT NOT NULL,
  date_read DATE NOT NULL,
  cover_url TEXT,
  user_id INTEGER
);
