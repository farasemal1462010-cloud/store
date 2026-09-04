const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET || 'development-secret-change-me';
const dataFile = process.env.DATA_FILE || path.join(__dirname, 'kidicare-data.json');

const seedProducts = [
  { id: 1, name: 'KidiTemp Pro Digital Thermometer', image: 'img/product-thermometer.jpg', price: 29.99, description: 'Fast, accurate temperature readings for everyday family care.', rating: '4.9 (312)' },
  { id: 2, name: 'KidiSafe Complete First Aid Kit', image: 'img/product-firstaid.jpg', price: 44.99, description: 'Essential first aid supplies for home and travel.', rating: '4.8 (247)' },
  { id: 3, name: 'KidiPulse Pediatric Oximeter', image: 'img/product-oximeter.jpg', price: 24.99, description: 'Simple, comfortable at-home wellness checks.', rating: '4.8 (189)' },
  { id: 4, name: 'KidiSoft Gentle Skin Care Set', image: 'img/product-skincare.jpg', price: 34.99, description: 'Gentle daily care made for delicate skin.', rating: '4.6 (415)' },
  { id: 5, name: 'KidiBreeze Compact Nebulizer', image: 'img/product-nebulizer.jpg', price: 59.99, description: 'A quieter, more comfortable care experience.', rating: '4.9 (156)' },
  { id: 6, name: 'KidiScan Forehead Thermometer', image: 'img/product-thermometer.jpg', price: 38.99, description: 'Quick, contactless temperature checks.', rating: '4.7 (203)' },
  { id: 7, name: 'KidiGuard Travel First Aid Pouch', image: 'img/product-firstaid.jpg', price: 19.99, description: 'Portable essentials for everyday adventures.', rating: '4.8 (91)' },
  { id: 8, name: 'KidiBand Wrist Health Monitor', image: 'img/product-oximeter.jpg', price: 42.99, description: 'Convenient wellness information close at hand.', rating: '4.9 (278)' }
];

function readData() {
  if (!fs.existsSync(dataFile)) {
    const initialData = { users: [], products: seedProducts, orders: [] };
    fs.writeFileSync(dataFile, JSON.stringify(initialData, null, 2));
    return initialData;
  }
  const storedData = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
  let migrated = false;
  if (!Array.isArray(storedData.users)) { storedData.users = []; migrated = true; }
  if (!Array.isArray(storedData.products)) { storedData.products = seedProducts; migrated = true; }
  if (!Array.isArray(storedData.orders)) { storedData.orders = []; migrated = true; }
  if (migrated) fs.writeFileSync(dataFile, JSON.stringify(storedData, null, 2));
  return storedData;
}

function writeData(data) {
  fs.writeFileSync(dataFile, JSON.stringify(data, null, 2));
}

const data = readData();
const ownerEmail = (process.env.OWNER_EMAIL || 'owner@kidicare.com').toLowerCase();
const ownerPassword = process.env.OWNER_PASSWORD || 'change-this-password';
if (!data.users.length) {
  data.users.push({ id: 1, email: ownerEmail, passwordHash: bcrypt.hashSync(ownerPassword, 12), role: 'owner' });
  writeData(data);
  console.warn(`Created owner account for ${ownerEmail}. Change OWNER_PASSWORD before production.`);
}

app.use(express.json({ limit: '50kb' }));
app.use(express.static(__dirname));

function authenticateOwner(req, res, next) {
  const authorization = req.headers.authorization || '';
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Owner authentication required.' });
  try {
    const payload = jwt.verify(token, jwtSecret);
    const owner = data.users.find(user => user.id === payload.id && user.role === 'owner');
    if (payload.role !== 'owner' || !owner) return res.status(403).json({ error: 'Owner access required.' });
    req.owner = payload;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired owner session.' });
  }
}

app.get('/api/dev/owner-session', (req, res) => {
  const localHost = req.hostname === 'localhost' || req.hostname === '127.0.0.1';
  const remoteAddress = req.socket && req.socket.remoteAddress;
  const isLoopback = remoteAddress === '127.0.0.1' || remoteAddress === '::1' || remoteAddress === '::ffff:127.0.0.1';
  const isLocalRequest = localHost && isLoopback;
  if (process.env.NODE_ENV === 'production' || !isLocalRequest) {
    return res.status(404).json({ error: 'Not found.' });
  }
  const owner = data.users.find(user => user.role === 'owner');
  if (!owner) return res.status(503).json({ error: 'Owner account is not configured.' });
  const token = jwt.sign({ id: owner.id, email: owner.email, role: owner.role }, jwtSecret, { expiresIn: '2h' });
  res.json({ token });
});

app.post('/api/auth/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = data.users.find(item => item.email === email);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, jwtSecret, { expiresIn: '8h' });
  res.json({ token, owner: { email: user.email, role: user.role } });
});

app.get('/api/products', (req, res) => res.json(data.products));

app.get('/api/products/:id', (req, res) => {
  const product = data.products.find(item => item.id === Number(req.params.id));
  if (!product) return res.status(404).json({ error: 'Product not found.' });
  res.json(product);
});

app.put('/api/products/:id', authenticateOwner, (req, res) => {
  const product = data.products.find(item => item.id === Number(req.params.id));
  if (!product) return res.status(404).json({ error: 'Product not found.' });
  const name = String(req.body.name || '').trim();
  const image = String(req.body.image || '').trim();
  const description = String(req.body.description || '').trim();
  const rating = String(req.body.rating || '').trim();
  const price = Number(req.body.price);
  if (!name || !image || !description || !rating || !Number.isFinite(price) || price < 0) {
    return res.status(400).json({ error: 'Name, image, description, rating, and a valid price are required.' });
  }
  Object.assign(product, { name, image, price, description, rating });
  writeData(data);
  res.json(product);
});

app.post('/api/products', authenticateOwner, (req, res) => {
  const name = String(req.body.name || '').trim();
  const image = String(req.body.image || '').trim();
  const description = String(req.body.description || '').trim();
  const rating = String(req.body.rating || '').trim();
  const price = Number(req.body.price);
  if (!name || !image || !description || !rating || !Number.isFinite(price) || price < 0) {
    return res.status(400).json({ error: 'Name, image, description, rating, and a valid price are required.' });
  }
  const nextId = data.products.reduce((highest, item) => Math.max(highest, item.id), 0) + 1;
  const product = { id: nextId, name, image, price, description, rating };
  data.products.push(product);
  writeData(data);
  res.status(201).json(product);
});

app.delete('/api/products/:id', authenticateOwner, (req, res) => {
  const productIndex = data.products.findIndex(item => item.id === Number(req.params.id));
  if (productIndex === -1) return res.status(404).json({ error: 'Product not found.' });
  data.products.splice(productIndex, 1);
  writeData(data);
  res.status(204).end();
});

const orderStatuses = ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'archived'];
const paymentMethods = ['card', 'paypal', 'cash'];

function asTrimmedString(value, maxLength) {
  const result = String(value == null ? '' : value).trim();
  return result.length <= maxLength ? result : result.slice(0, maxLength);
}

function roundCurrency(value) {
  return Math.round((value + Number.EPSILON) * 100) / 100;
}

function buildOrder(body) {
  const customer = body && body.customer && typeof body.customer === 'object' ? body.customer : body;
  const delivery = body && body.address && typeof body.address === 'object'
    ? body.address
    : body && body.shippingAddress && typeof body.shippingAddress === 'object' ? body.shippingAddress : body;
  const rawPayment = body && body.payment && typeof body.payment === 'object' ? body.payment.method : body && body.payment;
  const submittedPayment = asTrimmedString(body && (body.paymentMethod || rawPayment), 40).toLowerCase();
  const paymentMethod = ({ 'credit card': 'card', 'credit_card': 'card', 'credit or debit card': 'card', 'cash on delivery': 'cash', 'cash_on_delivery': 'cash' }[submittedPayment] || submittedPayment);
  const name = asTrimmedString(customer && (customer.name || customer.fullName), 120);
  const email = asTrimmedString(customer && customer.email, 160).toLowerCase();
  const phone = asTrimmedString(customer && customer.phone, 40);
  const street = asTrimmedString(delivery && (delivery.street || delivery.address || delivery.line1), 200);
  const city = asTrimmedString(delivery && delivery.city, 100);
  const postal = asTrimmedString(delivery && (delivery.postal || delivery.postalCode || delivery.zip), 30);
  const rawItems = body && Array.isArray(body.items) ? body.items : [];

  if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !phone || !street || !city || !postal) {
    return { error: 'Name, email, phone, street address, city, and postal code are required.' };
  }
  if (!paymentMethods.includes(paymentMethod)) {
    return { error: 'A valid payment method is required.' };
  }
  if (!rawItems.length || rawItems.length > 50) return { error: 'At least one order item is required.' };

  const items = [];
  for (const rawItem of rawItems) {
    const productId = Number(rawItem && (rawItem.productId != null ? rawItem.productId : rawItem.id));
    const quantity = Number(rawItem && rawItem.quantity);
    const product = data.products.find(item => item.id === productId);
    if (!product || !Number.isInteger(productId) || !Number.isInteger(quantity) || quantity < 1 || quantity > 99) {
      return { error: 'Each order item must reference a valid product and quantity.' };
    }
    const unitPrice = Number(product.price);
    if (!Number.isFinite(unitPrice) || unitPrice < 0) return { error: 'The selected product is not available.' };
    items.push({
      productId: product.id,
      name: product.name,
      image: product.image,
      price: roundCurrency(unitPrice),
      quantity,
      total: roundCurrency(unitPrice * quantity)
    });
  }

  const subtotal = roundCurrency(items.reduce((sum, item) => sum + item.total, 0));
  return {
    customer: { name, email, phone },
    address: { street, city, postal },
    items,
    payment: { method: paymentMethod },
    paymentMethod,
    subtotal,
    total: subtotal
  };
}

app.post('/api/orders', (req, res) => {
  const orderData = buildOrder(req.body || {});
  if (orderData.error) return res.status(400).json({ error: orderData.error });
  const now = new Date().toISOString();
  const order = {
    id: `order-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    ...orderData,
    status: 'pending',
    createdAt: now,
    updatedAt: now
  };
  data.orders.unshift(order);
  writeData(data);
  res.status(201).json(order);
});

app.get('/api/orders', authenticateOwner, (req, res) => {
  const submittedStatus = asTrimmedString(req.query.status, 20).toLowerCase();
  const requestedStatus = submittedStatus === 'all' ? '' : submittedStatus;
  if (requestedStatus && !orderStatuses.includes(requestedStatus)) {
    return res.status(400).json({ error: 'Unknown order status.' });
  }
  const includeArchived = req.query.includeArchived === '1' || req.query.includeArchived === 'true';
  const orders = data.orders.filter(order => {
    if (!includeArchived && order.status === 'archived') return false;
    return !requestedStatus || order.status === requestedStatus;
  });
  res.json(orders);
});

function findOrder(req, res) {
  const order = data.orders.find(item => item.id === req.params.id);
  if (!order) {
    res.status(404).json({ error: 'Order not found.' });
    return null;
  }
  return order;
}

app.get('/api/orders/:id', authenticateOwner, (req, res) => {
  const order = findOrder(req, res);
  if (order) res.json(order);
});

function updateOrderStatus(req, res) {
  const order = findOrder(req, res);
  if (!order) return;
  const status = asTrimmedString(req.body && req.body.status, 20).toLowerCase();
  if (!orderStatuses.includes(status) || status === 'archived') {
    return res.status(400).json({ error: 'A valid non-archived order status is required.' });
  }
  order.status = status;
  order.updatedAt = new Date().toISOString();
  writeData(data);
  res.json(order);
}

app.patch('/api/orders/:id/status', authenticateOwner, updateOrderStatus);
app.put('/api/orders/:id/status', authenticateOwner, updateOrderStatus);
app.patch('/api/orders/:id', authenticateOwner, updateOrderStatus);
app.put('/api/orders/:id', authenticateOwner, updateOrderStatus);

app.delete('/api/orders/:id', authenticateOwner, (req, res) => {
  const order = findOrder(req, res);
  if (!order) return;
  order.status = 'archived';
  order.updatedAt = new Date().toISOString();
  writeData(data);
  res.json(order);
});

app.listen(port, () => console.log(`Kidi Care server running at http://localhost:${port}`));
