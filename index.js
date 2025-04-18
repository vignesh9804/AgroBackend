import dotenv from "dotenv";
import express from "express";
import bodyParser  from "body-parser";
import { neon } from "@neondatabase/serverless";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { sendEmail } from "./emails/sendEmail.js";
import cors from 'cors';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;
const sql = neon(process.env.DATABASE_URL);

app.use(cors({
  origin: 'http://localhost:3000', // or use "*" for public APIs
  credentials: true, // if you're using cookies
}));

app.use(express.json());
app.use(bodyParser.json());

// Middleware to verify JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(404).send("Invalid user to access");
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(404).send("Invalid user to access");
  }
}

// Middleware to check admin
function checkAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).send("Only admin can perform this action");
  }
  next();
}


// Register
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, role, email} = req.body;

    if (!username || !password || !email) {
      return res.status(400).send("Incorrect details");
    }

    const hashed = await bcrypt.hash(password, 10);

    const result = await sql`
      INSERT INTO users (username, password, role, email)
      VALUES (${username}, ${hashed}, ${role || "buyer"}, ${email})
      RETURNING id, username, role;
    `;

    res.status(201).json({ user: result[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).send("Username or email already exists");
    }
    console.error("Register error:", err);
    res.status(500).send("Internal Server Error");
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).send("Incorrect details");
    }

    const result = await sql`
      SELECT * FROM users WHERE username = ${username};
    `;

    if (result.length === 0) {
      return res.status(404).send("User not found");
    }

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).send("Incorrect password");
    }

    const payload = { id: user.id, username: user.username, role: user.role };

    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "500h",
    });

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("Internal Server Error");
  }
});

// Get products (authenticated)
app.get("/api/products", verifyToken, async (req, res) => {
  try {
    const result = await sql`SELECT * FROM products;`;
    res.json(result);
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// Used to add products to cart
app.post("/api/addtocart", verifyToken, async (req, res) => {
  const { user_id, product_id, quantity } = req.body;

  if (!user_id || !product_id || !quantity) {
    return res.status(400).send("Missing required fields");
  }

  if (req.user.id !== user_id) {
    return res.status(403).send("User ID does not match token");
  }

  try {
    const existing = await sql`
      SELECT * FROM cart WHERE user_id = ${user_id} AND product_id = ${product_id};
    `;

    if (existing.length > 0) {
      // Update existing quantity
      await sql`
        UPDATE cart
        SET quantity_cart = quantity_cart + ${quantity}
        WHERE user_id = ${user_id} AND product_id = ${product_id};
      `;
    } else {
      // Insert new item into cart
      await sql`
        INSERT INTO cart (user_id, product_id, quantity_cart)
        VALUES (${user_id}, ${product_id}, ${quantity});
      `;
    }

    res.status(201).json({ message: "Item added/updated in cart successfully" });
  } catch (err) {
    console.error("Add to cart error:", err);
    res.status(500).send("Error adding item to cart");
  }
});


app.post("/api/cart", verifyToken, async (req, res) => {
  const { user_id } = req.body;

  if (!user_id) {
    return res.status(400).send("User ID is required");
  }

  if (req.user.id !== user_id) {
    return res.status(403).send("Invalid user to access");
  }

  try {
    const cartItems = await sql`
      SELECT 
        c.product_id, 
        c.quantity_cart, 
        p.name, 
        p.price, 
        p.image_url
      FROM cart c
      JOIN products p ON c.product_id = p.product_id
      WHERE c.user_id = ${user_id};
    `;

    res.status(200).json(cartItems);
  } catch (err) {
    console.error("Error fetching cart items:", err);
    res.status(500).send("Failed to fetch cart items");
  }
});



// Used to update product in cart
app.put("/api/cart/update", verifyToken, async (req, res) => {
  const { user_id, product_id, quantity } = req.body;

  if (!user_id || !product_id || !quantity) {
    return res.status(400).send("Missing required fields");
  }

  if (req.user.id !== user_id) {
    return res.status(403).send("User ID does not match token");
  }

  try {
    const result = await sql`
      UPDATE cart
      SET quantity_cart = ${quantity}
      WHERE user_id = ${user_id} AND product_id = ${product_id};
    `;

    // Check if row was actually updated
    if (result.count === 0) {
      return res.status(404).send("Cart item not found");
    }

    res.status(200).json({ message: "Cart quantity updated successfully" });
  } catch (err) {
    console.error("Update cart error:", err);
    res.status(500).send("Error updating cart item");
  }
});


// used to place order for items in the cart and send Email Notification
app.post("/api/orders", verifyToken, async (req, res) => {
  const { user_id, delivery_name, contact_info, address } = req.body;

  if (!user_id || !delivery_name || !contact_info || !address) {
    return res.status(400).send("Missing required fields");
  }

  if (req.user.id !== user_id) {
    return res.status(403).send("User ID does not match token");
  }

  try {
    const cartItems = await sql`
      SELECT c.product_id, c.quantity_cart, p.name, p.price
      FROM cart c
      JOIN products p ON c.product_id = p.product_id
      WHERE c.user_id = ${user_id};
    `;

    if (cartItems.length === 0) {
      return res.status(400).send("Cart is empty");
    }

    const orderResult = await sql`
      INSERT INTO orders (user_id, delivery_name, contact_info, address)
      VALUES (${user_id}, ${delivery_name}, ${contact_info}, ${address})
      RETURNING id;
    `;
    const orderId = orderResult[0].id;

    let totalCost = 0;
    const orderProducts = [];

    for (const item of cartItems) {
      await sql`
        INSERT INTO order_items (order_id, product_id, quantity)
        VALUES (${orderId}, ${item.product_id}, ${item.quantity_cart});
      `;
      totalCost += item.price * item.quantity_cart;
      orderProducts.push({ name: item.name, quantity: item.quantity_cart });
    }

    await sql`
      DELETE FROM cart WHERE user_id = ${user_id};
    `;

    const userResult = await sql`
      SELECT email FROM users WHERE id = ${user_id};
    `;
    const email = userResult[0]?.email;

    if (email) {
      const productList = orderProducts.map(p => `• ${p.name} (x${p.quantity})`).join("\n");

      const emailContent = `
Hi ${delivery_name},

✅ Your order has been placed successfully!

🧾 Order ID: ${orderId}
📦 Items:
${productList}

💰 Total Cost: ₹${totalCost}
📍 Delivery Address: ${address}

We'll notify you when your order is shipped. Thank you for shopping with us!

- Team
      `;

      await sendEmail(email, "Your Order Confirmation", emailContent);
    }

    res.status(201).json({ message: "Order placed and confirmation email sent", order_id: orderId });
  } catch (err) {
    console.error("Place order error:", err);
    res.status(500).send("Error placing order");
  }
});


app.post("/api/bulk-orders", verifyToken, async (req, res) => {
  const { user_id, product_id, quantity, delivery_name, contact_info, address } = req.body;

  if (!user_id || !product_id || !quantity || !delivery_name || !contact_info || !address) {
    return res.status(400).send("Missing required fields");
  }

  if (req.user.id !== user_id) {
    return res.status(403).send("User ID does not match token");
  }

  if (quantity < 10) {
    return res.status(400).send("Minimum quantity should be 10 or more");
  }

  try {
    const productResult = await sql`
      SELECT name, price FROM products WHERE product_id = ${product_id};
    `;

    if (productResult.length === 0) {
      return res.status(404).send("Product not found");
    }

    const { name: productName, price } = productResult[0];
    const totalCost = price * quantity;

    const orderResult = await sql`
      INSERT INTO orders (user_id, delivery_name, contact_info, address)
      VALUES (${user_id}, ${delivery_name}, ${contact_info}, ${address})
      RETURNING id;
    `;
    const orderId = orderResult[0].id;

    await sql`
      INSERT INTO order_items (order_id, product_id, quantity)
      VALUES (${orderId}, ${product_id}, ${quantity});
    `;

    const userResult = await sql`
      SELECT email FROM users WHERE id = ${user_id};
    `;
    const email = userResult[0]?.email;

    if (email) {
      const emailContent = `
Hi ${delivery_name},

✅ Your bulk order has been placed successfully!

🧾 Order ID: ${orderId}
📦 Product: ${productName}
🔢 Quantity: ${quantity}

💰 Total Cost: ₹${totalCost}
📍 Delivery Address: ${address}

Thank you for shopping in bulk with us!

- Team
      `;

      await sendEmail(email, "Bulk Order Confirmation", emailContent);
    }

    res.status(201).json({ message: "Bulk order placed successfully", order_id: orderId });
  } catch (err) {
    console.error("Bulk order error:", err);
    res.status(500).send("Error placing bulk order");
  }
});



// Used to get seperate order placed by user 
app.get("/api/orders/:id", verifyToken, async (req, res) => {
  const orderId = req.params.id;
  const userId = req.user.id;

  try {
    // Check if the order belongs to the logged-in user
    const order = await sql`
      SELECT * FROM orders WHERE id = ${orderId} AND user_id = ${userId};
    `;

    if (order.length === 0) {
      return res.status(404).send("Order not found or unauthorized access");
    }

    // Get order items
    const orderItems = await sql`
      SELECT oi.product_id, p.name, p.price, oi.quantity
      FROM order_items oi
      JOIN products p ON oi.product_id = p.id
      WHERE oi.order_id = ${orderId};
    `;

    res.status(200).json({
      order: order[0],
      items: orderItems,
    });
  } catch (err) {
    console.error("Get order details error:", err);
    res.status(500).send("Error fetching order details");
  }
});

// Used to get User all ordered products
app.post("/api/myorders", verifyToken, async (req, res) => {
  try {
    const { user_id } = req.body;

    const orders = await sql`
      SELECT 
        o.id AS order_id, 
        o.status,
        COUNT(oi.product_id) AS no_of_items,
        SUM(oi.quantity * pr.price) AS price,
        JSON_AGG(
          JSON_BUILD_OBJECT(
            'product_name', pr.name,
            'image_url', pr.image_url,
            'quantity', oi.quantity
          )
        ) AS products
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products pr ON oi.product_id = pr.product_id
      WHERE o.user_id = ${user_id}
      GROUP BY o.id
      ORDER BY o.id;
    `;

    res.status(200).json(orders);
  } catch (err) {
    console.error("User orders error:", err);
    res.status(500).send("Failed to retrieve user orders");
  }
});





// Used to get Delete Single Product in User Cart
app.delete("/api/cart/delete", verifyToken, async (req, res) => {
  const { user_id, product_id } = req.body;

  if (!user_id || !product_id) {
    return res.status(400).send("Missing required fields");
  }

  if (req.user.id !== user_id) {
    return res.status(403).send("User ID does not match token");
  }

  try {
    const result = await sql`
      DELETE FROM cart
      WHERE user_id = ${user_id} AND product_id = ${product_id};
    `;

    if (result.count === 0) {
      return res.status(404).send("Cart item not found");
    }

    res.status(200).json({ message: "Item removed from cart successfully" });
  } catch (err) {
    console.error("Delete cart item error:", err);
    res.status(500).send("Error deleting cart item");
  }
});




// --------------------Admin API's------------------------------


// Add product (admin only)
app.post("/api/admin/products", verifyToken, checkAdmin, async (req, res) => {
  try {
    const { name, price, image_url, product_type} = req.body;

    if (!name || !price || !image_url || !product_type) {
      return res.status(400).send("Missing required fields");
    }

    await sql`
      INSERT INTO products (name, price, image_url, product_type)
      VALUES (${name}, ${price}, ${image_url}, ${product_type});
    `;

    res.status(201).json({ message: "Product added successfully" });
  } catch (err) {
    res.status(500).send("Error adding product");
  }
});

app.get("/api/products/:id",verifyToken, async (req, res) => {
  const productId = req.params.id;

  try {
    const product = await sql`
      SELECT * FROM products WHERE product_id = ${productId};
    `;

    if (product.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json(product[0]);
  } catch (err) {
    console.error("Error fetching product:", err);
    res.status(500).send("Error fetching product");
  }
});


// Update product (admin only)
app.put("/api/admin/products/:id", verifyToken, checkAdmin, async (req, res) => {
  const productId = req.params.id;
  const { name, price, image_url, product_type} = req.body;

  if (!name || !price || !image_url || !product_type) {
    return res.status(400).send("Missing required fields");
  }

  try {
    await sql`
      UPDATE products
      SET name = ${name}, price = ${price}, image_url = ${image_url}, product_type = ${product_type}
      WHERE product_id = ${productId};
    `;

    res.json({ message: "Product updated successfully" });
  } catch (err) {
    res.status(500).send("Error updating product");
  }
});

// Used to get All Orders
app.get("/api/admin/orders", verifyToken, checkAdmin, async (req, res) => {
  try {
    const orders = await sql`
      SELECT 
        o.id as order_id, 
        o.user_id, 
        o.status, 
        o.delivery_name, 
        o.contact_info, 
        o.address,
        oi.product_id, 
        oi.quantity,
        p.name as product_name,
        p.image_url
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products p ON oi.product_id = p.product_id
      WHERE oi.quantity <=6
      ORDER BY o.id;
    `;

    res.status(200).json(orders);
  } catch (err) {
    console.error("Get orders error:", err);
    res.status(500).send("Failed to retrieve orders");
  }
});


// Used to Update order Status
app.put("/api/admin/orders/:id", verifyToken, checkAdmin, async (req, res) => {
  const { id } = req.params;
  const { status} = req.body;

  const allowedStatuses = ["Pending", "In Progress", "Completed"];
  if (!allowedStatuses.includes(status)) {
    return res.status(400).send("Invalid status value");
  }

  try {
    const result = await sql`
      UPDATE orders
      SET status = ${status}
      WHERE id = ${id}
      RETURNING *;
    `;

    if (result.length === 0) {
      return res.status(404).send("Order not found");
    }

    res.status(200).json({ message: "Order status updated successfully", order: result[0] });
  } catch (err) {
    console.error("Update order status error:", err);
    res.status(500).send("Failed to update order status");
  }
});


// GET Bulk Orders (quantity >= 10)
app.get("/api/admin/bulk-orders", verifyToken, checkAdmin, async (req, res) => {
  try {
    const bulkOrders = await sql`
      SELECT 
        o.id as order_id, 
        o.user_id, 
        o.status, 
        o.delivery_name, 
        o.contact_info, 
        o.address,
        oi.product_id, 
        oi.quantity,
        p.name as product_name,
        p.image_url
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products p ON oi.product_id = p.product_id
      WHERE oi.quantity >= 10
      ORDER BY o.id;
    `;

    res.status(200).json(bulkOrders);
  } catch (err) {
    console.error("Get bulk orders error:", err);
    res.status(500).send("Failed to retrieve bulk orders");
  }
});


// Used to delete Product 
app.delete("/api/admin/products/:id", verifyToken, checkAdmin, async (req, res) => {
  const productId = req.params.id;

  if (!productId) {
    return res.status(400).send("Missing product ID");
  }

  try {
    const result = await sql`
      DELETE FROM products WHERE id = ${productId};
    `;

    if (result.count === 0) {
      return res.status(404).send("Product not found");
    }

    res.status(200).json({ message: "Product deleted successfully" });
  } catch (err) {
    console.error("Delete product error:", err);
    res.status(500).send("Error deleting product");
  }
});


app.use((req, res) => {
  res.status(404).send("Route not found");
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
