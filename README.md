# Book Vault

A full-stack book notes app built with Express, EJS, and PostgreSQL.

## Features
- User authentication (Sign Up / Sign In / Logout)
- Server-side sessions with expiry
- Add, edit, delete book notes
- ISBN auto-fetch for title/author (Open Library API)
- Search, sort, and minimum rating filter
- Per-user book privacy (users only see their own books)

## Tech Stack
- Node.js
- Express
- EJS
- PostgreSQL (`pg`)

## Local Setup
1. Clone the repo:
```bash
git clone https://github.com/MosaLaxman/Book-Vault.git
cd Book-Vault
```

2. Install dependencies:
```bash
npm install
```

3. Create `.env` file:
```env
PORT=3000
DB_HOST=localhost
DB_PORT=5432
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
```

For cloud DB, you can set:
```env
DATABASE_URL=postgresql://username:password@host:port/dbname?sslmode=require
NODE_ENV=production
```

4. Run the app:
```bash
npm start
```

App runs on `http://localhost:3000`.

## Database Notes
On startup, the app auto-creates:
- `users` table
- `sessions` table
- `books.user_id` column (if missing)

If you are using a brand new database, create `books` table once:
```sql
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
```

## Free Deployment (Recommended)

### 1. GitHub
Push code to this repository:
`https://github.com/MosaLaxman/Book-Vault`

### 2. Neon (Free PostgreSQL)
1. Create a Neon project.
2. Copy the Neon connection string.
3. Run the `books` table SQL above once in Neon SQL Editor.

### 3. Render (Free Web Service)
1. Create a new Render Web Service from this repo.
2. Build command: `npm install`
3. Start command: `npm start`
4. Add environment variables:
   - `DATABASE_URL` = Neon connection string
   - `NODE_ENV` = `production`

Deploy and open the Render URL.

## Author
Laxman
