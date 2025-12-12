const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(helmet());
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});
app.disable('x-powered-by');

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore' }));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

app.post(
  '/read',
  body('filename')
    .exists()
    .bail()
    .isString()
    .trim()
    .notEmpty()
    .custom(value => {
      if (value.includes('\0')) throw new Error();
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);
    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }
    if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found' });

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';
  if (typeof filename !== 'string' || filename.includes('\0') || !filename.trim()) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const normalized = resolveSafe(BASE_DIR, filename);
  if (!normalized.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: 'Path traversal detected' });
  }
  if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found', path: normalized });
  const content = fs.readFileSync(normalized, 'utf8');
  res.json({ path: normalized, content });
});

app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };
  Object.keys(samples).forEach(k => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });
  res.json({ ok: true, base: BASE_DIR });
});

if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
