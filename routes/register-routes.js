const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
require("dotenv").config();
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRESIN = process.env.JWT_EXPIRESIN;

// User registration
router.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username,
      password: hashedPassword,
    });

    const savedUser = await newUser.save();

    const authToken = jwt.sign(
      { _id: savedUser._id, userName: savedUser.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRESIN }
    );
    return res.json({ token: authToken, user: savedUser });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Setup 2FA
router.post("/setup-2fa", async (req, res) => {
  const { userId } = req.body;
  const user = await User.findById(userId);

  const secret = speakeasy.generateSecret({ length: 20 });
  user.twoFASecret = secret.base32;

  await user.save();

  qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
    res.json({ qrCodeUrl: data_url });
  });
});

//User 2FA check
router.post("/check-2fa", async (req, res) => {
  const authHeader = req.headers["authorization"];

  const athToken = authHeader.split(" ")[1];

  decodedToken = jwt.verify(athToken, JWT_SECRET);
  const userId = decodedToken._id;

  const { token: userToken, enable } = req.body;
  console.log("🚀 ~ router.post ~ enable:", enable);
  const user = await User.findById(userId);

  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  if (user.is2FAEnabled) {
    const verified = speakeasy.totp.verify({
      secret: user.twoFASecret,
      encoding: "base32",
      token: userToken,
    });

    if (!verified) {
      return res.status(400).json({ error: "Invalid 2FA token" });
    }
  }

  if (enable) {
    const user2 = await User.findByIdAndUpdate(userId, {
      is2FAEnabled: enable,
    });
    console.log("🚀 ~ router.post ~ user2:", user2);
  }
  res.status(200).json({
    status: "success",
  });
});

// User login
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ error: "Invalid password" });
  }

  const authToken = jwt.sign(
    { _id: user._id, userName: user.username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRESIN }
  );
  res
    .header("auth-token", authToken)
    .json({ token: authToken, is2FAEnabled: user.is2FAEnabled, id: user._id });
});

module.exports = router;
