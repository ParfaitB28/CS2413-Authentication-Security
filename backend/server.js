const express = require('express');

const app = express();
const port = 3000;

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(port, '127.0.0.1', () => {
  console.log(`Server running at http://127.0.0.1:${port}`);
});
