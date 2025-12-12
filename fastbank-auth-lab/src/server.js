const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const csrf = require('lusca').csrf;

const app = express();
const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.disable("x-powered-by");

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 12)
  }
];

const sessions = {};

function findUser(username) {
  return users.find((u) => u.username === username);
}

function getAuthenticatedUser(req) {
  const token = req.cookies.session;
  if (!token || !sessions[token]) return null;
  const session = sessions[token];
  return users.find((u) => u.id === session.userId) || null;
}

app.get("/api/me", (req, res) => {
  const user = getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = findUser(username);

  const genericFail = () =>
    res.status(401).json({ success: false, message: "Invalid credentials" });

  if (!user) return genericFail();

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return genericFail();

  const token = crypto.randomBytes(48).toString("hex");

  sessions[token] = {
    userId: user.id,
    expires: Date.now() + 1000 * 60 * 30
  };

  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 1000 * 60 * 30
  });

  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token) delete sessions[token];
  res.clearCookie("session");
  res.json({ success: true });
});

setInterval(() => {
  const now = Date.now();
  for (const token in sessions) {
    if (sessions[token].expires < now) delete sessions[token];
  }
}, 60 * 1000);

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
