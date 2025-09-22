const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const validator = require('validator');
const ObjectId = mongoose.Types.ObjectId;

// --- Setup ---
// IMPORTANT: Load environment variables from .env file
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// --- Database Connection ---
// It is recommended to use the environment variable for your MongoDB URI
const mongoURI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/komsyte';
mongoose.connect(mongoURI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error(err));

// Ensure the uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}
app.use('/uploads', express.static(uploadsDir));

// --- Multer Configuration for Image Uploads ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    },
});
const upload = multer({ storage: storage });

// --- MongoDB Schemas and Models ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['Owner', 'Manager', 'Waiter', 'Chef'], required: true },
    restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Restaurant', required: true },
    phone: String,
    payRate: Number,
});
const User = mongoose.model('User', UserSchema);

const RestaurantSchema = new mongoose.Schema({
    shopName: { type: String, required: true },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    logo: String,
});
const Restaurant = mongoose.model('Restaurant', RestaurantSchema);

const MenuItemSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String,
    price: { type: Number, required: true },
    category: String,
    restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Restaurant', required: true },
    image: String,
});
const MenuItem = mongoose.model('MenuItem', MenuItemSchema);

const TableSchema = new mongoose.Schema({
    name: { type: String, required: true },
    restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Restaurant', required: true },
    qrCodeUrl: String, // Stored URL of the QR code
});
const Table = mongoose.model('Table', TableSchema);

const OrderSchema = new mongoose.Schema({
    restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Restaurant', required: true },
    tableId: { type: mongoose.Schema.Types.ObjectId, ref: 'Table' },
    items: [
        {
            menuItemId: { type: mongoose.Schema.Types.ObjectId, ref: 'MenuItem', required: true },
            name: String,
            quantity: { type: Number, required: true },
            price: { type: Number, required: true },
            status: { type: String, enum: ['Placed', 'Sent to Kitchen', 'Preparing', 'Ready', 'Delivered'], default: 'Placed' }
        },
    ],
    totalAmount: { type: Number, required: true },
    orderType: { type: String, enum: ['Dine-In', 'Dine-In-QR', 'Delivery', 'Takeout'], default: 'Dine-In' },
    status: { type: String, enum: ['Pending', 'Completed', 'Canceled'], default: 'Pending' },
    kotNumber: { type: Number },
    createdAt: { type: Date, default: Date.now },
});
const Order = mongoose.model('Order', OrderSchema);

const BillSchema = new mongoose.Schema({
    restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Restaurant', required: true },
    tableId: { type: mongoose.Schema.Types.ObjectId, ref: 'Table' },
    orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order' },
    items: [
        {
            menuItemId: { type: mongoose.Schema.Types.ObjectId, ref: 'MenuItem', required: true },
            name: String,
            quantity: Number,
            price: Number,
        },
    ],
    totalAmount: { type: Number, required: true },
    staffId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Staff member who closed the bill
    paymentMethod: { type: String, enum: ['Cash', 'Card', 'UPI', 'Other'] },
    createdAt: { type: Date, default: Date.now },
});
const Bill = mongoose.model('Bill', BillSchema);


// --- Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// Middleware to check if the user has a required role
const checkRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).send({ error: 'Access denied. Insufficient permissions.' });
        }
        next();
    };
};

// --- Routes ---

// Route for initial restaurant/owner registration
app.post('/api/register', async (req, res) => {
    const { shopName, name, email, password } = req.body;
    if (!shopName || !name || !email || !password) {
        return res.status(400).send({ error: 'Please provide all required fields.' });
    }
    if (!validator.isEmail(email)) {
        return res.status(400).send({ error: 'Invalid email format.' });
    }
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).send({ error: 'User with this email already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newRestaurant = new Restaurant({ shopName });
        await newRestaurant.save();

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            role: 'Owner',
            restaurantId: newRestaurant._id,
        });
        await newUser.save();

        newRestaurant.owner = newUser._id;
        await newRestaurant.save();

        const token = jwt.sign({
            userId: newUser._id,
            email: newUser.email,
            restaurantId: newRestaurant._id,
            role: newUser.role
        }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.status(201).send({ message: 'Registration successful', token });
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Server error during registration.' });
    }
});

// Route for user login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send({ error: 'Email and password are required.' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send({ error: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign({
            userId: user._id,
            email: user.email,
            restaurantId: user.restaurantId,
            role: user.role
        }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.send({ token, role: user.role });
    } catch (err) {
        res.status(500).send({ error: 'Server error during login.' });
    }
});

// Route for adding a new employee
app.post('/api/employees', authenticateToken, checkRole(['Owner', 'Manager']), async (req, res) => {
    const { name, email, password, role, phone, payRate } = req.body;

    // Basic validation
    if (!name || !email || !password || !role) {
        return res.status(400).send({ error: 'Please provide name, email, password, and role.' });
    }
    if (!validator.isEmail(email)) {
        return res.status(400).send({ error: 'Invalid email format.' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).send({ error: 'An employee with this email already exists.' });
        }

        // Hash the password for security
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newEmployee = new User({
            name,
            email,
            password: hashedPassword,
            role,
            restaurantId: req.user.restaurantId,
            phone,
            payRate,
        });

        await newEmployee.save();

        res.status(201).send({ message: 'Employee added successfully!' });
    } catch (err) {
        console.error('Employee registration error:', err);
        res.status(500).send({ error: 'Failed to add employee.' });
    }
});

// Route to get all employees for a restaurant
app.get('/api/employees', authenticateToken, async (req, res) => {
    try {
        const employees = await User.find({ restaurantId: req.user.restaurantId }).select('-password');
        res.send(employees);
    } catch (err) {
        res.status(500).send({ error: 'Failed to fetch employees.' });
    }
});

// Route to delete an employee
app.delete('/api/employees/:id', authenticateToken, checkRole(['Owner', 'Manager']), async (req, res) => {
    try {
        const employeeId = req.params.id;
        const employee = await User.findById(employeeId);

        if (!employee) {
            return res.status(404).send({ error: 'Employee not found.' });
        }

        // Prevent owners or managers from deleting the restaurant owner
        if (employee.role === 'Owner') {
            return res.status(403).send({ error: 'Cannot delete the restaurant owner.' });
        }

        // Ensure the employee belongs to the same restaurant
        if (employee.restaurantId.toString() !== req.user.restaurantId) {
            return res.status(403).send({ error: 'You do not have permission to delete this employee.' });
        }

        await User.findByIdAndDelete(employeeId);
        res.send({ message: 'Employee deleted successfully.' });
    } catch (err) {
        console.error('Delete employee error:', err);
        res.status(500).send({ error: 'Failed to delete employee.' });
    }
});

// Route to get the currently logged-in user's profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).send({ error: 'User not found.' });
        }
        res.send(user);
    } catch (err) {
        res.status(500).send({ error: 'Failed to fetch profile.' });
    }
});

// Route to update a user's profile
app.put('/api/profile', authenticateToken, async (req, res) => {
    const { name, email, phone } = req.body;
    try {
        const updatedUser = await User.findByIdAndUpdate(
            req.user.userId,
            { name, email, phone },
            { new: true, runValidators: true }
        ).select('-password');
        res.send({ message: 'Profile updated successfully', user: updatedUser });
    } catch (err) {
        res.status(500).send({ error: 'Failed to update profile.' });
    }
});

// Route to get a single user's details by ID (e.g., for reporting)
app.get('/api/user/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user || user.restaurantId.toString() !== req.user.restaurantId) {
            return res.status(404).send({ error: 'User not found.' });
        }
        res.send(user);
    } catch (err) {
        res.status(500).send({ error: 'Failed to fetch user details.' });
    }
});

// --- Menu Routes ---

// Route to add a new menu item
app.post('/api/menu', authenticateToken, checkRole(['Owner', 'Manager', 'Chef']), upload.single('image'), async (req, res) => {
    const { name, description, price, category } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    if (!name || !price) {
        return res.status(400).send({ error: 'Name and price are required.' });
    }

    try {
        const newMenuItem = new MenuItem({
            name,
            description,
            price,
            category,
            restaurantId: req.user.restaurantId,
            image: imageUrl,
        });

        await newMenuItem.save();
        res.status(201).send(newMenuItem);
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Failed to add menu item.' });
    }
});

// Route to get all menu items for a restaurant
app.get('/api/menu', authenticateToken, async (req, res) => {
    try {
        const menuItems = await MenuItem.find({ restaurantId: req.user.restaurantId }).sort('category');
        res.send(menuItems);
    } catch (err) {
        res.status(500).send({ error: 'Failed to fetch menu items.' });
    }
});

// Route to delete a menu item
app.delete('/api/menu/:id', authenticateToken, checkRole(['Owner', 'Manager']), async (req, res) => {
    try {
        const item = await MenuItem.findById(req.params.id);
        if (!item || item.restaurantId.toString() !== req.user.restaurantId) {
            return res.status(404).send({ error: 'Menu item not found.' });
        }

        // Optional: delete image file from server
        if (item.image) {
            const imagePath = path.join(__dirname, item.image);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        }

        await MenuItem.findByIdAndDelete(req.params.id);
        res.send({ message: 'Menu item deleted successfully.' });
    } catch (err) {
        res.status(500).send({ error: 'Failed to delete menu item.' });
    }
});

// Route to update a menu item
app.put('/api/menu/:id', authenticateToken, checkRole(['Owner', 'Manager']), upload.single('image'), async (req, res) => {
    const { name, description, price, category } = req.body;
    const updateData = { name, description, price, category };

    try {
        const item = await MenuItem.findById(req.params.id);
        if (!item || item.restaurantId.toString() !== req.user.restaurantId) {
            return res.status(404).send({ error: 'Menu item not found.' });
        }

        if (req.file) {
            if (item.image) {
                const oldImagePath = path.join(__dirname, item.image);
                if (fs.existsSync(oldImagePath)) {
                    fs.unlinkSync(oldImagePath);
                }
            }
            updateData.image = `/uploads/${req.file.filename}`;
        }

        const updatedItem = await MenuItem.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, runValidators: true }
        );
        res.send(updatedItem);

    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Failed to update menu item.' });
    }
});

// --- Table Routes ---

// Route to get all tables
app.get('/api/tables', authenticateToken, async (req, res) => {
    try {
        const tables = await Table.find({ restaurantId: req.user.restaurantId });
        res.send(tables);
    } catch (err) {
        res.status(500).send({ error: 'Failed to fetch tables.' });
    }
});

// Route to create a new table
app.post('/api/tables', authenticateToken, checkRole(['Owner', 'Manager']), async (req, res) => {
    const { name } = req.body;
    if (!name) {
        return res.status(400).send({ error: 'Table name is required.' });
    }
    try {
        const newTable = new Table({
            name,
            restaurantId: req.user.restaurantId,
        });
        await newTable.save();
        res.status(201).send(newTable);
    } catch (err) {
        res.status(500).send({ error: 'Failed to create table.' });
    }
});

// Route to delete a table
app.delete('/api/tables/:id', authenticateToken, checkRole(['Owner', 'Manager']), async (req, res) => {
    try {
        const table = await Table.findById(req.params.id);
        if (!table || table.restaurantId.toString() !== req.user.restaurantId) {
            return res.status(404).send({ error: 'Table not found.' });
        }
        await Table.findByIdAndDelete(req.params.id);
        res.send({ message: 'Table deleted successfully.' });
    } catch (err) {
        res.status(500).send({ error: 'Failed to delete table.' });
    }
});

// --- Order & Bill Routes ---

// Route for staff to place an order from the POS
app.post('/api/order', authenticateToken, checkRole(['Owner', 'Manager', 'Waiter']), async (req, res) => {
    const { tableId, items, totalAmount, orderType = 'Dine-In' } = req.body;

    if (!items || items.length === 0 || !totalAmount) {
        return res.status(400).send({ error: 'Order must contain items and a total amount.' });
    }

    try {
        const lastKot = await Order.findOne({ restaurantId: req.user.restaurantId }).sort({ kotNumber: -1 });
        const newKotNumber = lastKot && lastKot.kotNumber ? lastKot.kotNumber + 1 : 1;

        const newOrder = new Order({
            restaurantId: req.user.restaurantId,
            tableId,
            items: items.map(item => ({ ...item, status: 'Sent to Kitchen' })),
            totalAmount,
            orderType,
            kotNumber: newKotNumber,
        });

        await newOrder.save();
        res.status(201).send({ message: 'Order placed successfully', orderId: newOrder._id });
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Failed to place order.' });
    }
});

// Route for kitchen to get all active orders
app.get('/api/kds', authenticateToken, checkRole(['Owner', 'Manager', 'Chef']), async (req, res) => {
    try {
        const activeOrders = await Order.find({
            restaurantId: req.user.restaurantId,
            status: 'Pending',
            'items.status': { $in: ['Sent to Kitchen', 'Preparing', 'Ready'] }
        })
        .populate('tableId', 'name')
        .sort({ createdAt: 1 });

        res.send(activeOrders);
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Failed to fetch KDS orders.' });
    }
});

// Route for kitchen to update an item's status
app.put('/api/kds/:orderId/item/:itemId', authenticateToken, checkRole(['Owner', 'Manager', 'Chef']), async (req, res) => {
    const { orderId, itemId } = req.params;
    const { newStatus } = req.body;

    if (!newStatus) {
        return res.status(400).send({ error: 'New status is required.' });
    }

    try {
        const order = await Order.findOne({ _id: orderId, restaurantId: req.user.restaurantId });
        if (!order) {
            return res.status(404).send({ error: 'Order not found.' });
        }

        const item = order.items.id(itemId);
        if (!item) {
            return res.status(404).send({ error: 'Item not found in order.' });
        }

        item.status = newStatus;
        await order.save();
        res.send({ message: `Item status updated to ${newStatus}.` });

    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Failed to update item status.' });
    }
});

// Route to get all active orders for POS
app.get('/api/order/active', authenticateToken, async (req, res) => {
    try {
        const orders = await Order.find({ restaurantId: req.user.restaurantId, status: 'Pending' })
            .populate('tableId', 'name')
            .sort({ createdAt: -1 });
        res.send(orders);
    } catch (err) {
        res.status(500).send({ error: 'Failed to fetch active orders.' });
    }
});

// Route to add items to an existing order (used by POS)
app.put('/api/order/:id/add-items', authenticateToken, checkRole(['Owner', 'Manager', 'Waiter']), async (req, res) => {
    const { items } = req.body;
    const orderId = req.params.id;

    if (!items || items.length === 0) {
        return res.status(400).send({ error: 'No items provided to add.' });
    }

    try {
        const order = await Order.findOne({ _id: orderId, restaurantId: req.user.restaurantId });
        if (!order) {
            return res.status(404).send({ error: 'Order not found.' });
        }

        let totalAmountAdded = 0;
        const newItems = items.map(item => {
            totalAmountAdded += item.price * item.quantity;
            return { ...item, status: 'Sent to Kitchen' };
        });

        order.items.push(...newItems);
        order.totalAmount += totalAmountAdded;
        await order.save();

        res.send({ message: 'Items added to order successfully.' });
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Failed to add items to order.' });
    }
});

// Route to get a single order by ID
app.get('/api/order/:id', authenticateToken, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order || order.restaurantId.toString() !== req.user.restaurantId) {
            return res.status(404).send({ error: 'Order not found.' });
        }
        res.send(order);
    } catch (err) {
        res.status(500).send({ error: 'Failed to fetch order.' });
    }
});

// Route to complete an order and create a bill
app.post('/api/order/:id/complete', authenticateToken, async (req, res) => {
    const orderId = req.params.id;
    const { paymentMethod, tableId } = req.body;

    try {
        const order = await Order.findById(orderId);
        if (!order || order.restaurantId.toString() !== req.user.restaurantId) {
            return res.status(404).send({ error: 'Order not found.' });
        }

        // Check if all items are delivered
        const allItemsDelivered = order.items.every(item => item.status === 'Delivered');
        if (!allItemsDelivered) {
            return res.status(400).send({ error: 'Cannot complete order. Not all items have been delivered.' });
        }

        order.status = 'Completed';
        await order.save();

        const newBill = new Bill({
            restaurantId: order.restaurantId,
            orderId: order._id,
            tableId: tableId,
            items: order.items,
            totalAmount: order.totalAmount,
            staffId: req.user.userId,
            paymentMethod: paymentMethod || 'Cash'
        });
        await newBill.save();

        res.send({ message: 'Order completed and bill created successfully.', billId: newBill._id });
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Failed to complete order.' });
    }
});

// --- Public Routes for Customer Menu (QR Code) ---

// Route for customer to view public menu
app.get('/api/public/menu', async (req, res) => {
    const { shopId } = req.query;
    if (!shopId) {
        return res.status(400).send({ error: 'Shop ID is required.' });
    }

    try {
        const restaurant = await Restaurant.findById(shopId);
        if (!restaurant) {
            return res.status(404).send({ error: 'Restaurant not found.' });
        }
        const menu = await MenuItem.find({ restaurantId: shopId }).sort('category');
        res.send({ restaurant, menu });
    } catch (err) {
        res.status(500).send({ error: 'Failed to fetch menu.' });
    }
});

// Route for customer to place an order
app.post('/api/public/order', async (req, res) => {
    const { tableId, items, totalAmount, orderType = 'Dine-In-QR', customerDetails } = req.body;

    if (!items || items.length === 0 || !totalAmount) {
        return res.status(400).send({ error: 'Order must contain items and a total amount.' });
    }

    try {
        const table = await Table.findById(tableId);
        if (!table) {
            return res.status(404).send({ error: 'Invalid table ID.' });
        }

        const lastKot = await Order.findOne({ restaurantId: table.restaurantId }).sort({ kotNumber: -1 });
        const newKotNumber = lastKot && lastKot.kotNumber ? lastKot.kotNumber + 1 : 1;

        const newOrder = new Order({
            restaurantId: table.restaurantId,
            tableId,
            items: items.map(item => ({ ...item, status: 'Placed' })), // Customer orders start as 'Placed'
            totalAmount,
            orderType,
            kotNumber: newKotNumber,
            customerDetails,
        });

        await newOrder.save();
        res.status(201).send({ message: 'Order placed successfully', orderId: newOrder._id });
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Failed to place order.' });
    }
});

// Route to get a specific order's live status for customer view
app.get('/api/public/order/status/:id', async (req, res) => {
    try {
        const order = await Order.findById(req.params.id).populate('tableId', 'name');
        if (!order) {
            return res.status(404).send({ error: 'Order not found.' });
        }
        res.send(order);
    } catch (err) {
        res.status(500).send({ error: 'Failed to fetch order status.' });
    }
});

// --- Reports Dashboard Routes ---
app.get('/api/reports/dashboard', authenticateToken, async (req, res) => {
    try {
        // Daily sales chart data
        const salesData = await Bill.aggregate([
            { $match: { restaurantId: new ObjectId(req.user.restaurantId) } },
            {
                $group: {
                    _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
                    totalSales: { $sum: '$totalAmount' }
                }
            },
            { $sort: { _id: 1 } },
            { $limit: 30 }
        ]);

        // Top selling items
        const topSellingItems = await Bill.aggregate([
            { $match: { restaurantId: new ObjectId(req.user.restaurantId) } },
            { $unwind: '$items' },
            {
                $group: {
                    _id: '$items.menuItemId',
                    name: { $first: '$items.name' },
                    totalQuantity: { $sum: '$items.quantity' }
                }
            },
            { $sort: { totalQuantity: -1 } },
            { $limit: 10 }
        ]);

        const totalRevenueResult = await Bill.aggregate([
            { $match: { restaurantId: new ObjectId(req.user.restaurantId) } },
            { $group: { _id: null, total: { $sum: '$totalAmount' } } }
        ]);
        const totalRevenue = totalRevenueResult.length > 0 ? totalRevenueResult[0].total : 0;

        res.send({
            totalRevenue,
            dailySales: salesData,
            topSellingItems,
        });

    } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'Failed to fetch reports.' });
    }
});

// ✅ NEW ROUTE: Dedicated endpoint for employee performance data
app.get('/api/reports/employee-performance', authenticateToken, async (req, res) => {
    try {
        const employeePerformance = await Bill.aggregate([
            { $match: { restaurantId: new ObjectId(req.user.restaurantId) } },
            {
                $group: {
                    _id: '$staffId',
                    totalSales: { $sum: '$totalAmount' },
                    billsCount: { $sum: 1 }
                }
            },
            { $sort: { totalSales: -1 } }
        ]);

        const employeeIds = employeePerformance.map(emp => emp._id);
        const employees = await User.find({ _id: { $in: employeeIds } }).select('name');
        const employeeMap = new Map(employees.map(emp => [emp._id.toString(), emp.name]));

        const performanceWithNames = employeePerformance.map(emp => ({
            workerId: emp._id,
            workerName: employeeMap.get(emp._id.toString()) || 'Unknown',
            totalSales: emp.totalSales,
            billsCount: emp.billsCount,
            aov: emp.totalSales / emp.billsCount
        }));

        res.send(performanceWithNames);

    } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'Failed to fetch employee performance report.' });
    }
});


// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));