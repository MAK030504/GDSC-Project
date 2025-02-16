const express = require("express");
const { register, login, forgotPassword, resetPassword } = require("../controllers/authController");
const passport = require("passport");
require("../config/passport");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

// Google OAuth Routes
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get("/google/callback", passport.authenticate("google", { session: false }), (req, res) => {
    res.json({ token: req.user.token, user: req.user.user });
});

module.exports = router;
