const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'mock_ecom_jwt_secret_key';

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/mock-ecom-cart', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { timestamps: true });

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  image: { type: String, required: true },
  description: { type: String },
}, { timestamps: true });

const cartItemSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, required: true, default: 1 },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const CartItem = mongoose.model('CartItem', cartItemSchema);

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.userId).select('-password');
    next();
  } catch (error) {
    res.status(401).json({ error: 'Token is not valid' });
  }
};

// Initialize Products
const initializeProducts = async () => {
  const productsCount = await Product.countDocuments();
  if (productsCount === 0) {
    const mockProducts = [
      { name: 'Wireless Headphones', price: 99.99, image: 'https://www.pexels.com/photo/concrete-road-between-trees-1563356/', description: 'High-quality wireless headphones with noise cancellation' },
      { name: 'Smart Watch', price: 199.99, image: 'https://www.pexels.com/photo/concrete-road-between-trees-1563356/', description: 'Feature-rich smartwatch with health monitoring' },
      { name: 'Laptop Backpack', price: 49.99, image: 'https://www.pexels.com/photo/concrete-road-between-trees-1563356/', description: 'Durable laptop backpack with multiple compartments' },
      { name: 'Bluetooth Speaker', price: 79.99, image: 'https://www.pexels.com/photo/concrete-road-between-trees-1563356/', description: 'Portable Bluetooth speaker with excellent sound quality' },
      { name: 'Phone Case', price: 19.99, image: 'https://www.pexels.com/photo/concrete-road-between-trees-1563356/', description: 'Protective phone case with stylish design' },
      { name: 'USB-C Cable', price: 15.99, image: 'https://www.pexels.com/photo/concrete-road-between-trees-1563356/', description: 'Fast charging USB-C cable, 2m length' },
      { name: 'Wireless Mouse', price: 29.99, image: 'https://www.pexels.com/photo/concrete-road-between-trees-1563356/', description: 'Ergonomic wireless mouse with precision tracking' },
      { name: 'Monitor Stand', price: 39.99, image: 'https://www.pexels.com/photo/concrete-road-between-trees-1563356/', description: 'Adjustable monitor stand for better ergonomics' }
    ];
    await Product.insertMany(mockProducts);
    console.log('Mock products added to database');
  }
};

// Auth Routes

// Register
app.post('/api/auth/register', [
  body('name').notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ name, email, password: hashedPassword });
    await user.save();

    const payload = { userId: user.id };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      token, 
      user: { id: user.id, name: user.name, email: user.email } 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').exists().withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const payload = { userId: user.id };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      token, 
      user: { id: user.id, name: user.name, email: user.email } 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/auth/me - Get current user
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user.id,
        name: req.user.name,
        email: req.user.email
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Product Routes

// GET /api/products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Cart Routes (Protected)

// GET /api/cart
app.get('/api/cart', authMiddleware, async (req, res) => {
  try {
    const cartItems = await CartItem.find({ user: req.user.id }).populate('product');
    
    const items = cartItems.map(item => ({
      id: item.product._id,
      name: item.product.name,
      price: item.product.price,
      image: item.product.image,
      quantity: item.quantity,
      cartItemId: item._id
    }));

    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    
    res.json({ items, total: parseFloat(total.toFixed(2)) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/cart
app.post('/api/cart', authMiddleware, async (req, res) => {
  try {
    const { productId, quantity = 1 } = req.body;

    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    let cartItem = await CartItem.findOne({ 
      user: req.user.id, 
      product: productId 
    });

    if (cartItem) {
      cartItem.quantity += quantity;
      await cartItem.save();
    } else {
      cartItem = new CartItem({
        user: req.user.id,
        product: productId,
        quantity: quantity
      });
      await cartItem.save();
    }

    await cartItem.populate('product');
    
    const cartItems = await CartItem.find({ user: req.user.id }).populate('product');
    const items = cartItems.map(item => ({
      id: item.product._id,
      name: item.product.name,
      price: item.product.price,
      image: item.product.image,
      quantity: item.quantity,
      cartItemId: item._id
    }));

    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    
    res.json({ items, total: parseFloat(total.toFixed(2)) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/cart/:id
app.delete('/api/cart/:id', authMiddleware, async (req, res) => {
  try {
    await CartItem.findOneAndDelete({ 
      _id: req.params.id, 
      user: req.user.id 
    });

    const cartItems = await CartItem.find({ user: req.user.id }).populate('product');
    const items = cartItems.map(item => ({
      id: item.product._id,
      name: item.product.name,
      price: item.product.price,
      image: item.product.image,
      quantity: item.quantity,
      cartItemId: item._id
    }));

    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    
    res.json({ items, total: parseFloat(total.toFixed(2)) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/cart/:id
app.put('/api/cart/:id', authMiddleware, async (req, res) => {
  try {
    const { quantity } = req.body;
    
    if (quantity < 1) {
      return res.status(400).json({ error: 'Quantity must be at least 1' });
    }

    const cartItem = await CartItem.findOneAndUpdate(
      { _id: req.params.id, user: req.user.id },
      { quantity },
      { new: true }
    ).populate('product');

    if (!cartItem) {
      return res.status(404).json({ error: 'Cart item not found' });
    }

    const cartItems = await CartItem.find({ user: req.user.id }).populate('product');
    const items = cartItems.map(item => ({
      id: item.product._id,
      name: item.product.name,
      price: item.product.price,
      image: item.product.image,
      quantity: item.quantity,
      cartItemId: item._id
    }));

    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    
    res.json({ items, total: parseFloat(total.toFixed(2)) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/checkout - Clear cart after successful checkout
app.post('/api/checkout', authMiddleware, async (req, res) => {
  try {
    const { customerInfo } = req.body;

    const cartItems = await CartItem.find({ user: req.user.id }).populate('product');
    const items = cartItems.map(item => ({
      id: item.product._id,
      name: item.product.name,
      price: item.product.price,
      quantity: item.quantity
    }));

    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    const receipt = {
      orderId: 'ORD' + Date.now(),
      customer: customerInfo,
      items: items,
      total: parseFloat(total.toFixed(2)),
      timestamp: new Date().toISOString(),
      status: 'confirmed'
    };

    // Clear user's cart after checkout - FIXED
    await CartItem.deleteMany({ user: req.user.id });

    res.json(receipt);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/checkout
app.post('/api/checkout', authMiddleware, async (req, res) => {
  try {
    const { customerInfo } = req.body;

    const cartItems = await CartItem.find({ user: req.user.id }).populate('product');
    const items = cartItems.map(item => ({
      id: item.product._id,
      name: item.product.name,
      price: item.product.price,
      quantity: item.quantity
    }));

    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    const receipt = {
      orderId: 'ORD' + Date.now(),
      customer: customerInfo,
      items: items,
      total: parseFloat(total.toFixed(2)),
      timestamp: new Date().toISOString(),
      status: 'confirmed'
    };

    // Clear user's cart after checkout
    await CartItem.deleteMany({ user: req.user.id });

    res.json(receipt);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Initialize products and start server
initializeProducts().then(() => {
  app.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
  });
});