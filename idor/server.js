const express = require("express");
const app = express();

app.use(express.json());

const users = [
  { id: 1, name: "Alice", role: "customer", department: "north" },
  { id: 2, name: "Bob", role: "customer", department: "south" },
  { id: 3, name: "Charlie", role: "support", department: "north" },
];

const orders = [
  { id: 1, userId: 1, item: "Laptop", region: "north", total: 2000 },
  { id: 2, userId: 1, item: "Mouse", region: "north", total: 40 },
  { id: 3, userId: 2, item: "Monitor", region: "south", total: 300 },
  { id: 4, userId: 2, item: "Keyboard", region: "south", total: 60 },
];

function fakeAuth(req, res, next) {
  const idHeader = req.header("X-User-Id");
  if (!idHeader || !/^\d+$/.test(idHeader)) {
    return res.status(401).json({ error: "Unauthenticated" });
  }
  const id = parseInt(idHeader, 10);
  const user = users.find((u) => u.id === id);
  if (!user) {
    return res.status(401).json({ error: "Unauthenticated" });
  }
  req.user = user;
  next();
}

app.use(fakeAuth);

app.get("/orders/:id", (req, res) => {
  const orderId = parseInt(req.params.id, 10);
  if (!Number.isInteger(orderId)) {
    return res.status(400).json({ error: "Invalid order id" });
  }

  const order = orders.find((o) => o.id === orderId);
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  if (order.userId !== req.user.id && req.user.role !== "support") {
    return res.status(403).json({ error: "Forbidden" });
  }

  return res.json(order);
});

app.get("/", (req, res) => {
  res.json({ message: "Access Control Tutorial API", currentUser: req.user });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
