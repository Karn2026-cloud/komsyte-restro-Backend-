// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ---------------- App Setup ----------------
const app = express();
app.use(express.json());

// Create uploads dir if missing and serve static files
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) { fs.mkdirSync(uploadsDir); }
app.use('/uploads', express.static(uploadsDir));

// ---------------- CORS Setup ----------------
// Provide ALLOWED_ORIGINS as comma-separated env variable if needed.
// Fallback includes common local dev URLs and your Render frontend.
const defaultOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'https://komsyte-restro-frontend.onrender.com'
];
const allowedOrigins = (process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : defaultOrigins);

app.use(cors({
  origin: function(origin, callback){
    // allow requests with no origin (like mobile apps, curl, postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    } else {
      return callback(new Error('CORS policy: This origin is not allowed'), false);
    }
  },
  methods: "GET,POST,PUT,DELETE,OPTIONS",
  credentials: true
}));

// ---------------- MongoDB Connection ----------------
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/komsyte';

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(async () => {
    console.log('✅ MongoDB connected');

    // --- Fix: Remove accidental unique index on shops.email if exists ---
    // This helps fix the E11000 duplicate key error you encountered earlier
    try {
      const coll = mongoose.connection.collection('shops');
      const indexes = await coll.indexes();
      const hasEmailIndex = indexes.some(idx => idx.key && idx.key.email === 1);
      if (hasEmailIndex) {
        console.log('⚠️ Dropping shops.email index to avoid duplicate key errors...');
        await coll.dropIndex('email_1');
        console.log('✅ Dropped shops.email index');
      }
    } catch (idxErr) {
      // Ignore if index doesn't exist or permission denied in managed DB
      if (idxErr.codeName === 'IndexNotFound' || idxErr.message.includes('index not found')) {
        console.log('No shops.email index found. Skipping drop.');
      } else {
        console.warn('Could not drop shops.email index (you may need to remove it manually in Mongo Atlas):', idxErr.message);
      }
    }
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// ---------------- Constants & Multer Setup ----------------
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key';

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir + '/'),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

// ===================================================================
//                        Mongoose Schemas
// ===================================================================

const shopSchema = new mongoose.Schema({
  shopName: { type: String, required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker' },
  kotCounter: { type: Number, default: 0 }
});

const workerSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['Owner', 'Manager', 'Waiter', 'Chef', 'Cashier', 'Staff'], default: 'Staff' },
  restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true },
  phone: { type: String, default: '' },
  payRate: { type: Number, default: 0 }
});

const menuItemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  imageUrl: { type: String },
  isAvailable: { type: Boolean, default: true },
  attributes: { description: String, isVeg: Boolean },
  restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true }
});

const tableSchema = new mongoose.Schema({
  name: { type: String, required: true },
  capacity: { type: Number, default: 4 },
  isTemporary: { type: Boolean, default: false },
  restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true }
});

const orderSchema = new mongoose.Schema({
  tableId: { type: mongoose.Schema.Types.ObjectId, ref: 'Table' },
  items: [{
    menuItemId: { type: mongoose.Schema.Types.ObjectId, ref: 'MenuItem' },
    name: String,
    quantity: Number,
    price: Number,
    status: { type: String, default: 'Sent to Kitchen' }
  }],
  totalAmount: { type: Number, required: true },
  status: { type: String, enum: ['Active', 'Billed', 'Closed'], default: 'Active' },
  orderType: { type: String, enum: ['Dine-In', 'Takeaway', 'Delivery', 'Dine-In-QR'], default: 'Dine-In' },
  customerDetails: { name: String, phone: String, address: String },
  kotNumber: { type: Number },
  restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true }
}, { timestamps: true });

const billSchema = new mongoose.Schema({
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true },
  totalAmount: { type: Number, required: true },
  paymentMode: { type: String, default: 'Cash' },
  billNumber: { type: String, required: true },
  workerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker' },
  restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true }
}, { timestamps: true });

const attendanceSchema = new mongoose.Schema({
  workerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker', required: true },
  restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true },
  clockInTime: { type: Date, required: true },
  clockOutTime: { type: Date }
});

// ---------------- Mongoose Models ----------------
const Shop = mongoose.model('Shop', shopSchema);
const Worker = mongoose.model('Worker', workerSchema);
const MenuItem = mongoose.model('MenuItem', menuItemSchema);
const Table = mongoose.model('Table', tableSchema);
const Order = mongoose.model('Order', orderSchema);
const Bill = mongoose.model('Bill', billSchema);
const Attendance = mongoose.model('Attendance', attendanceSchema);

// ===================================================================
//                        Middleware
// ===================================================================
const auth = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const worker = await Worker.findById(decoded.workerId).select('-password');
    if (!worker) throw new Error('Worker not found');
    req.worker = worker;
    next();
  } catch (err) {
    console.warn('Auth error:', err.message);
    res.status(401).json({ error: 'Invalid token.' });
  }
};

const checkRole = (allowedRoles) => (req, res, next) => {
  if (!req.worker || !allowedRoles.includes(req.worker.role)) {
    return res.status(403).json({ error: 'Forbidden: You do not have the required permissions.' });
  }
  next();
};

// ===================================================================
//                        API Routes
// ===================================================================

// ---------------- Auth Routes ----------------
app.post('/api/signup', async (req, res) => {
  try {
    const { shopName, email, password } = req.body;
    if (!shopName || !email || !password) {
      return res.status(400).json({ error: 'Please provide all required fields.' });
    }

    const existing = await Worker.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already in use.' });

    const newShop = new Shop({ shopName });
    await newShop.save();

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const owner = new Worker({
      name: 'Owner',
      email,
      password: hashedPassword,
      role: 'Owner',
      restaurantId: newShop._id
    });
    await owner.save();

    newShop.owner = owner._id;
    await newShop.save();

    res.status(201).json({ success: true, message: 'Restaurant and Owner account created successfully!' });
  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    // send safe error message to client; full err logged on server
    res.status(500).json({ error: 'Server error during signup.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const worker = await Worker.findOne({ email });
    if (!worker) return res.status(400).json({ error: 'Invalid credentials.' });

    const isMatch = await bcrypt.compare(password, worker.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials.' });

    const token = jwt.sign({ workerId: worker._id, role: worker.role }, JWT_SECRET, { expiresIn: '1d' });
    res.json({
      token,
      user: { _id: worker._id, name: worker.name, email: worker.email, role: worker.role, restaurantId: worker.restaurantId }
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// ---------------- Public Customer Routes ----------------
app.get('/api/public/menu', async (req, res) => {
  try {
    const { shopId } = req.query;
    if (!shopId) return res.status(400).json({ error: 'Shop ID is required.' });

    const shop = await Shop.findById(shopId);
    if (!shop) return res.status(404).json({ error: 'Restaurant not found.' });

    const menuItems = await MenuItem.find({ restaurantId: shopId, isAvailable: true });
    res.json({ menuItems, shopName: shop.shopName });
  } catch (err) {
    console.error("Error fetching public menu:", err);
    res.status(500).json({ error: 'Server error fetching menu.' });
  }
});

app.post('/api/public/orders', async (req, res) => {
  try {
    const { shopId, items, existingOrderId, orderType } = req.body;
    if (!shopId || !items) return res.status(400).json({ error: 'shopId and items are required.' });

    const shop = await Shop.findById(shopId);
    if (!shop) return res.status(404).json({ error: 'Restaurant not found.' });

    if (existingOrderId) {
      const order = await Order.findById(existingOrderId);
      if (!order) return res.status(404).json({ error: 'Existing order not found.' });
      if (order.status !== 'Active') return res.status(400).json({ error: 'Cannot add items to a closed order.' });

      items.forEach(item => order.items.push(item));
      order.totalAmount = order.items.reduce((acc, item) => acc + (item.price * item.quantity), 0);
      await order.save();

      return res.status(200).json({ message: 'Items added to order.', orderId: order._id, kotNumber: order.kotNumber });
    }

    shop.kotCounter += 1;

    const tempTable = new Table({
      name: `Guest #${shop.kotCounter}`,
      isTemporary: true,
      restaurantId: shopId
    });
    await tempTable.save();

    const totalAmount = items.reduce((acc, item) => acc + (item.price * item.quantity), 0);

    const newOrder = new Order({
      tableId: tempTable._id,
      items: items.map(item => ({ ...item, status: 'Sent to Kitchen' })),
      totalAmount,
      restaurantId: shopId,
      kotNumber: shop.kotCounter,
      orderType: orderType || 'Dine-In-QR',
      status: 'Active'
    });

    await shop.save();
    await newOrder.save();
    res.status(201).json({ message: 'Order created.', orderId: newOrder._id, kotNumber: newOrder.kotNumber });
  } catch (err) {
    console.error("Error creating/updating public order:", err);
    res.status(500).json({ error: 'Server error while placing order.' });
  }
});

// ---------------- Role Definitions for easier management ----------------
const managementRoles = ['Owner', 'Manager'];
const orderTakingRoles = ['Owner', 'Manager', 'Waiter'];
const kitchenRoles = ['Owner', 'Manager', 'Chef'];

// ---------------- Profile & Employee Routes (Owner, Manager) ----------------
app.get('/api/profile', auth, checkRole(managementRoles), async (req, res) => {
  try {
    const user = await Worker.findById(req.worker._id).populate('restaurantId');
    const employees = await Worker.find({ restaurantId: req.worker.restaurantId });

    const performance = await Bill.aggregate([
      { $match: { restaurantId: new mongoose.Types.ObjectId(req.worker.restaurantId) } },
      { $group: { _id: '$workerId', billsCount: { $sum: 1 }, totalSales: { $sum: '$totalAmount' } } },
      { $lookup: { from: 'workers', localField: '_id', foreignField: '_id', as: 'workerInfo' } },
      { $unwind: '$workerInfo' },
      { $project: { _id: 0, workerId: '$_id', workerName: '$workerInfo.name', billsCount: 1, totalSales: 1 } }
    ]);

    res.json({ user, employees, performance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error fetching profile data.' });
  }
});

app.post('/api/employees', auth, checkRole(managementRoles), async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const existingWorker = await Worker.findOne({ email });
    if (existingWorker) return res.status(400).json({ error: 'Email is already in use.' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newEmployee = new Worker({
      name, email, password: hashedPassword, role,
      restaurantId: req.worker.restaurantId
    });
    await newEmployee.save();
    res.status(201).json(newEmployee);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error adding employee.' });
  }
});

app.delete('/api/employees/:id', auth, checkRole(managementRoles), async (req, res) => {
  try {
    const employee = await Worker.findOne({ _id: req.params.id, restaurantId: req.worker.restaurantId });
    if (!employee) return res.status(404).json({ error: 'Employee not found.' });
    if (employee.role === 'Owner') return res.status(400).json({ error: 'Cannot delete the owner account.' });

    await Worker.findByIdAndDelete(req.params.id);
    res.json({ message: 'Employee removed.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error deleting employee.' });
  }
});

// ---------------- Menu & Table Routes (Owner, Manager) ----------------
app.get('/api/menu', auth, checkRole(managementRoles), async (req, res) => {
  try {
    const menuItems = await MenuItem.find({ restaurantId: req.worker.restaurantId });
    res.json(menuItems);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error fetching menu.' });
  }
});

app.post('/api/menu', auth, checkRole(managementRoles), upload.single('image'), async (req, res) => {
  try {
    const { name, price, category, description, isVeg, isAvailable } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    const newMenuItem = new MenuItem({
      name, price, category, imageUrl,
      isAvailable: isAvailable === 'true',
      attributes: { description, isVeg: isVeg === 'true' },
      restaurantId: req.worker.restaurantId
    });
    await newMenuItem.save();
    res.status(201).json(newMenuItem);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error adding menu item.' });
  }
});

app.put('/api/menu/:id', auth, checkRole(managementRoles), upload.single('image'), async (req, res) => {
  try {
    const { name, price, category, description, isVeg, isAvailable } = req.body;

    const updateData = {};
    if (name) updateData.name = name;
    if (price) updateData.price = price;
    if (category) updateData.category = category;
    if (isAvailable !== undefined) {
      updateData.isAvailable = String(isAvailable).toLowerCase() === 'true';
    }

    if (description !== undefined || isVeg !== undefined) {
      const existingItem = await MenuItem.findById(req.params.id);
      updateData.attributes = existingItem.attributes || {};
      if (description !== undefined) updateData.attributes.description = description;
      if (isVeg !== undefined) updateData.attributes.isVeg = String(isVeg).toLowerCase() === 'true';
    }

    if (req.file) {
      updateData.imageUrl = `/uploads/${req.file.filename}`;
    }

    const updatedItem = await MenuItem.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true });

    if (!updatedItem) return res.status(404).json({ error: 'Menu item not found.' });
    res.json(updatedItem);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error updating menu item.' });
  }
});

app.delete('/api/menu/:id', auth, checkRole(managementRoles), async (req, res) => {
  try {
    const deletedItem = await MenuItem.findOneAndDelete({ _id: req.params.id, restaurantId: req.worker.restaurantId });
    if (!deletedItem) return res.status(404).json({ error: 'Menu item not found.' });
    res.json({ message: 'Menu item deleted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error deleting menu item.' });
  }
});

app.get('/api/tables', auth, checkRole(managementRoles), async (req, res) => {
  try {
    const tables = await Table.find({ restaurantId: req.worker.restaurantId });
    res.json(tables);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error fetching tables.' });
  }
});

app.post('/api/tables', auth, checkRole(managementRoles), async (req, res) => {
  try {
    const { name, capacity } = req.body;
    const newTable = new Table({ name, capacity, restaurantId: req.worker.restaurantId, isTemporary: false });
    await newTable.save();
    res.status(201).json(newTable);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error adding table.' });
  }
});

app.delete('/api/tables/:id', auth, checkRole(managementRoles), async (req, res) => {
  try {
    const deletedTable = await Table.findOneAndDelete({ _id: req.params.id, restaurantId: req.worker.restaurantId });
    if (!deletedTable) return res.status(404).json({ error: 'Table not found.' });
    res.json({ message: 'Table deleted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error deleting table.' });
  }
});

// ---------------- Order & Billing Routes (Owner, Manager, Waiter) ----------------
app.get('/api/orders/active', auth, checkRole(orderTakingRoles), async (req, res) => {
  try {
    const activeOrders = await Order.find({ restaurantId: req.worker.restaurantId, status: 'Active' }).populate('tableId');
    res.json(activeOrders);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error fetching active orders.' });
  }
});

app.post('/api/orders', auth, checkRole(orderTakingRoles), async (req, res) => {
  try {
    const { tableId, items, orderType, customerDetails } = req.body;
    if (!items || !Array.isArray(items)) return res.status(400).json({ error: 'Items array is required.' });

    const totalAmount = items.reduce((acc, item) => acc + (item.price * item.quantity), 0);

    const newOrder = new Order({
      tableId: orderType === 'Dine-In' ? tableId : null,
      items, totalAmount, orderType, customerDetails,
      restaurantId: req.worker.restaurantId,
      status: 'Active'
    });
    await newOrder.save();
    res.status(201).json(newOrder);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error creating order.' });
  }
});

app.put('/api/orders/:id/items', auth, checkRole(orderTakingRoles), async (req, res) => {
  try {
    const { items } = req.body;
    if (!items || !Array.isArray(items)) return res.status(400).json({ error: 'Items array is required.' });

    const totalAmount = items.reduce((acc, item) => acc + (item.price * item.quantity), 0);

    const updatedOrder = await Order.findOneAndUpdate(
      { _id: req.params.id, restaurantId: req.worker.restaurantId },
      { $set: { items, totalAmount } }, { new: true }
    );
    if (!updatedOrder) return res.status(404).json({ error: 'Order not found.' });
    res.json(updatedOrder);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error updating order items.' });
  }
});

app.post('/api/bills', auth, checkRole(orderTakingRoles), async (req, res) => {
  try {
    const { orderId, paymentMode } = req.body;
    if (!orderId) return res.status(400).json({ error: 'orderId is required.' });

    const order = await Order.findById(orderId);
    if (!order || order.restaurantId.toString() !== req.worker.restaurantId.toString()) {
      return res.status(404).json({ error: 'Order not found.' });
    }
    if (order.status !== 'Active') return res.status(400).json({ error: 'Order is not active.' });

    const newBill = new Bill({
      orderId,
      totalAmount: order.totalAmount,
      paymentMode,
      billNumber: `BILL-${Date.now()}`,
      workerId: req.worker._id,
      restaurantId: req.worker.restaurantId
    });
    await newBill.save();

    order.status = 'Billed';
    await order.save();

    if (order.tableId) {
      const relatedTable = await Table.findById(order.tableId);
      if (relatedTable && relatedTable.isTemporary) {
        await Table.findByIdAndDelete(relatedTable._id);
      }
    }

    res.status(201).json(newBill);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error creating bill.' });
  }
});

app.get('/api/bills', auth, checkRole(orderTakingRoles), async (req, res) => {
  try {
    const bills = await Bill.find({ restaurantId: req.worker.restaurantId })
      .populate({ path: 'orderId', populate: { path: 'tableId' } })
      .populate('workerId', 'name')
      .sort({ createdAt: -1 });
    res.json(bills);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error fetching bills.' });
  }
});

// ---------------- KDS Routes (Owner, Manager, Chef) ----------------
app.get('/api/kds', auth, checkRole(kitchenRoles), async (req, res) => {
  try {
    const kitchenOrders = await Order.find({
      restaurantId: req.worker.restaurantId,
      status: 'Active',
      'items.status': { $in: ['Sent to Kitchen', 'Preparing'] }
    }).populate('tableId');
    res.json(kitchenOrders);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error fetching KDS data.' });
  }
});

app.put('/api/orders/:orderId/item/:itemId', auth, checkRole(kitchenRoles), async (req, res) => {
  try {
    const { status } = req.body;
    const { orderId, itemId } = req.params;

    const result = await Order.updateOne(
      { _id: orderId, 'items._id': itemId, restaurantId: req.worker.restaurantId },
      { $set: { 'items.$.status': status } }
    );

    // modern driver returns modifiedCount
    if ((result.modifiedCount ?? result.nModified) === 0) return res.status(404).json({ error: 'Order or item not found.' });
    res.json({ message: 'Item status updated.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error updating item status.' });
  }
});

// ---------------- Report Routes (Owner, Manager) ----------------
app.get('/api/reports/dashboard', auth, checkRole(managementRoles), async (req, res) => {
  try {
    const { restaurantId } = req.worker;
    const restaurantObjectId = new mongoose.Types.ObjectId(restaurantId);

    const kpis = await Bill.aggregate([
      { $match: { restaurantId: restaurantObjectId } },
      { $group: { _id: null, totalRevenue: { $sum: '$totalAmount' }, totalOrders: { $sum: 1 } } }
    ]);

    const salesTrend = await Bill.aggregate([
      { $match: { restaurantId: restaurantObjectId } },
      { $group: {
        _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
        dailySales: { $sum: '$totalAmount' }
      }},
      { $sort: { _id: 1 } },
      { $limit: 30 }
    ]);

    const topItems = await Order.aggregate([
      { $match: { restaurantId: restaurantObjectId, status: { $in: ['Billed', 'Closed'] } } },
      { $unwind: '$items' },
      { $group: {
        _id: '$items.name',
        totalQuantitySold: { $sum: '$items.quantity' }
      }},
      { $sort: { totalQuantitySold: -1 } },
      { $limit: 5 }
    ]);

    const employeePerformance = await Bill.aggregate([
      { $match: { restaurantId: restaurantObjectId, workerId: { $exists: true } } },
      { $group: { _id: '$workerId', billsCount: { $sum: 1 }, totalSales: { $sum: '$totalAmount' } } },
      { $lookup: { from: 'workers', localField: '_id', foreignField: '_id', as: 'workerInfo' } },
      { $unwind: '$workerInfo' },
      { $project: { _id: 0, workerId: '$_id', workerName: '$workerInfo.name', billsCount: 1, totalSales: 1 } },
      { $sort: { totalSales: -1 } }
    ]);

    const kpiData = kpis[0] || { totalRevenue: 0, totalOrders: 0 };

    res.json({
      kpis: {
        totalRevenue: kpiData.totalRevenue,
        totalOrders: kpiData.totalOrders,
        averageOrderValue: kpiData.totalOrders > 0 ? kpiData.totalRevenue / kpiData.totalOrders : 0
      },
      salesTrend,
      topItems,
      employeePerformance
    });

  } catch (err) {
    console.error("Dashboard Report Error:", err);
    res.status(500).json({ error: 'Server error fetching dashboard report.' });
  }
});

// ---------------- Server Listen ----------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
