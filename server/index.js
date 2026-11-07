
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import Razorpay from "razorpay";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 5000);

app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:5173"
}));

app.use(express.json({ limit: "20kb" }));

app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 40,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

const otpStore = new Map();
const verifiedPhones = new Set();

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  message: { error: "Too many OTP requests. Try again later." }
});

const razorpayReady = () =>
  process.env.RAZORPAY_KEY_ID &&
  process.env.RAZORPAY_KEY_SECRET &&
  !process.env.RAZORPAY_KEY_ID.includes("your_key");

app.post("/api/request-otp", otpLimiter, async (req, res) => {
  const phone = String(req.body.phone || "").trim();
  const digits = phone.replace(/\D/g, "");

  if (!/^\+?[0-9\s-]+$/.test(phone) || digits.length < 10 || digits.length > 15) {
    return res.status(400).json({ error: "Enter a valid phone number." });
  }

  if (
    !process.env.TWILIO_ACCOUNT_SID ||
    !process.env.TWILIO_AUTH_TOKEN ||
    !process.env.TWILIO_PHONE_NUMBER
  ) {
    otpStore.set(phone, {
      otp: "123456",
      expires: Date.now() + 5 * 60 * 1000,
      attempts: 0
    });

    return res.json({
      message: "Development OTP generated. Use 123456.",
      demoOtp: "123456"
    });
  }

  return res.status(503).json({
    error: "SMS sending integration has not been configured."
  });
});

app.post("/api/verify-otp", (req, res) => {
  const phone = String(req.body.phone || "").trim();
  const otp = String(req.body.otp || "").trim();
  const record = otpStore.get(phone);

  if (!record || Date.now() > record.expires) {
    return res.status(400).json({
      error: "OTP expired. Request a new one."
    });
  }

  record.attempts += 1;

  if (record.attempts > 5) {
    otpStore.delete(phone);
    return res.status(429).json({
      error: "Too many attempts. Request a new OTP."
    });
  }

  if (record.otp !== otp) {
    return res.status(400).json({ error: "Incorrect OTP." });
  }

  otpStore.delete(phone);
  verifiedPhones.add(phone);

  res.json({ success: true });
});

app.post("/api/create-order", async (req, res) => {
  const { amount, currency = "INR", customer } = req.body;

  if (
    !customer?.phone ||
    !verifiedPhones.has(String(customer.phone).trim())
  ) {
    return res.status(403).json({
      error: "Verify your phone number before payment."
    });
  }

  if (!customer?.name || !customer?.email || !customer?.consultingFor) {
    return res.status(400).json({
      error: "Please complete the consultation form."
    });
  }

  if (!razorpayReady()) {
    return res.status(503).json({
      error: "Payment is not configured yet. Add Razorpay test keys."
    });
  }

  try {
    const razorpay = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_KEY_SECRET
    });

    const order = await razorpay.orders.create({
      amount: Number(amount || 999) * 100,
      currency,
      receipt: `consult_${Date.now()}`
    });

    res.json({
      id: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    res.status(500).json({
      error: "Unable to create payment order. Check Razorpay configuration."
    });
  }
});

app.post("/api/verify-payment", (req, res) => {
  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature
  } = req.body;

  if (!razorpayReady()) {
    return res.status(503).json({
      error: "Payment is not configured."
    });
  }

  const expected = crypto
    .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest("hex");

  const a = Buffer.from(expected);
  const b = Buffer.from(String(razorpay_signature || ""));

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(400).json({
      error: "Payment signature could not be verified."
    });
  }

  res.json({ success: true });
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.use(express.static(path.resolve(__dirname, "../dist")));

app.use((req, res, next) => {
  if (req.method === "GET" && !req.path.startsWith("/api/")) {
    return res.sendFile(
      path.resolve(__dirname, "../dist/index.html")
    );
  }

  next();
});

app.listen(port, () => {
  console.log(`API server running on port ${port}`);
});
