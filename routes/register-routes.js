const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");

// User registration
router.post("/register", async (req, res) => {
  const { username, password, enable2FA } = req.body;

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username,
      password: hashedPassword,
    });

    // If user opts to enable 2FA during registration
    if (enable2FA) {
      const secret = speakeasy.generateSecret({ length: 20 });
      newUser.twoFASecret = secret.base32;
      newUser.is2FAEnabled = true;

      // Generate QR code for 2FA setup
      qrcode.toDataURL(secret.otpauth_url, async (err, data_url) => {
        if (err) {
          return res.status(500).json({ error: "Error generating QR code" });
        }

        const savedUser = await newUser.save();
        return res.json({ user: savedUser, qrCodeUrl: data_url });
      });
    } else {
      const savedUser = await newUser.save();
      return res.json({ user: savedUser });
    }
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
  user.is2FAEnabled = true;

  await user.save();

  qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
    res.json({ qrCodeUrl: data_url });
  });
});

// User login
router.post("/login", async (req, res) => {
  const { username, password, token: userToken } = req.body;
  const user = await User.findOne({ username });

  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ error: "Invalid password" });
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

  const authToken = jwt.sign({ _id: user._id }, "SECRET_KEY");
  res.header("auth-token", authToken).json({ token: authToken });
});

module.exports = router;
