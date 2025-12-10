const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 12)
  }
];

const sessions = {};
const loginAttempts = {};
const MAX_TRIES = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;

function cleanupExpiredSessions() {
  const now = Date.now();
  for (const t in sessions) {
    if (sessions[t].expires && sessions[t].expires <= now) {
      delete sessions[t];
    }
  }
}

setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

function findUser(username) {
  if (typeof username !== "string") return null;
  const name = username.trim();
  return users.find((u) => u.username === name);
}

function isValidCredentialInput(obj) {
  if (!obj || typeof obj !== "object") return false;
  if (typeof obj.username !== "string" || typeof obj.password !== "string") return false;
  if (obj.username.length === 0 || obj.password.length === 0) return false;
  return true;
}

app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }

  const session = sessions[token];
  if (session.expires && session.expires <= Date.now()) {
    delete sessions[token];
    res.clearCookie("session", cookieOptions());
    return res.status(401).json({ authenticated: false });
  }

  const user = users.find((u) => u.id === session.userId);
  if (!user) {
    return res.status(401).json({ authenticated: false });
  }

  res.json({ authenticated: true, username: user.username });
});

function cookieOptions() {
  const isProd = process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    secure: !!isProd,
    sameSite: "Lax",
    maxAge: 24 * 60 * 60 * 1000
  };
}

app.post("/api/login", async (req, res) => {
  if (!isValidCredentialInput(req.body)) {
    return res.status(400).json({ success: false, message: "Invalid credentials" });
  }

  const { username, password } = req.body;
  const now = Date.now();
  const attempts = loginAttempts[username] || { tries: 0, firstAttemptTs: now };

  if (now - attempts.firstAttemptTs > LOCKOUT_WINDOW_MS) {
    attempts.tries = 0;
    attempts.firstAttemptTs = now;
  }

  if (attempts.tries >= MAX_TRIES) {
    return res.status(429).json({ success: false, message: "Too many attempts. Try later." });
  }

  const user = findUser(username);
  const dummyHash = "$2b$12$C6UzMDM.H6dfI/f/IKcZaeu";
  const hashToCompare = user ? user.passwordHash : dummyHash;

  let passwordMatches = false;
  try {
    passwordMatches = await bcrypt.compare(password, hashToCompare);
  } catch (err) {
    passwordMatches = false;
  }

  if (!user || !passwordMatches) {
    attempts.tries += 1;
    loginAttempts[username] = attempts;
    return res.status(401).json({ success: false, message: "Invalid username or password" });
  }

  delete loginAttempts[username];

  const token = crypto.randomBytes(32).toString("hex");
  const sessionExpiry = Date.now() + 24 * 60 * 60 * 1000;

  sessions[token] = { userId: user.id, expires: sessionExpiry };

  res.cookie("session", token, cookieOptions());
  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session", cookieOptions());
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
