const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const csurf = require("csurf");

const app = express();
const PORT = process.env.PORT || 3001;

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
);

app.use(bodyParser.urlencoded({ extended: false, limit: "10kb" }));
app.use(bodyParser.json({ limit: "10kb" }));

const COOKIE_SECRET = process.env.COOKIE_SECRET || "please-set-a-real-secret-in-prod";
app.use(cookieParser(COOKIE_SECRET));

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
  if (name.length === 0 || name.length > 150) return null;
  return users.find((u) => u.username === name);
}

function isValidCredentialInput(obj) {
  if (!obj || typeof obj !== "object") return false;
  if (typeof obj.username !== "string" || typeof obj.password !== "string") return false;
  const uname = obj.username.trim();
  if (uname.length === 0 || uname.length > 150) return false;
  if (obj.password.length === 0 || obj.password.length > 200) return false;
  return true;
}

function cookieOptions() {
  const isProd = process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    secure: !!isProd,
    signed: true,
    sameSite: "Strict",
    path: "/",
    maxAge: 24 * 60 * 60 * 1000
  };
}

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(apiLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: "Too many login attempts from this IP, try later." },
  standardHeaders: true,
  legacyHeaders: false
});

const csrfProtection = csurf({
  cookie: {
    key: "_csrf",
    httpOnly: true,
    sameSite: "Strict",
    secure: process.env.NODE_ENV === "production",
    signed: true
  }
});

app.get("/api/csrf-token", (req, res, next) => {
  csrfProtection(req, res, (err) => {
    if (err) return next(err);
    res.json({ csrfToken: req.csrfToken() });
  });
});

app.get("/api/me", (req, res) => {
  const token = req.signedCookies && req.signedCookies.session;
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

app.post("/api/login", loginLimiter, csrfProtection, async (req, res) => {
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

app.post("/api/logout", csrfProtection, (req, res) => {
  const token = req.signedCookies && req.signedCookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session", cookieOptions());
  res.json({ success: true });
});

app.use((err, req, res, next) => {
  const isProd = process.env.NODE_ENV === "production";
  if (!isProd) {
    console.error(err);
  }
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({ success: false, message: "Invalid CSRF token" });
  }
  res.status(500).json({ success: false, message: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
