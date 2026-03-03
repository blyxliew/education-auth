require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// ================= DATABASE =================

mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));

// ================= SCHEMA =================

const userSchema = new mongoose.Schema({
    name: String,
    role: String,
    roleId: String,
    email: String,
    password: String
});

const User = mongoose.model("User", userSchema);

// ================= REGISTER =================

app.post("/register", async (req, res) => {

    const { name, role, roleId, email, password } = req.body;

    try {
        const existingUser = await User.findOne({
            $or: [{ email }, { roleId }]
        });

        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            role,
            roleId,
            email,
            password: hashedPassword
        });

        await newUser.save();

        res.json({ message: "Registration successful" });

    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// ================= LOGIN =================

app.post("/login", async (req, res) => {

    const { loginId, password } = req.body;

    try {

        const user = await User.findOne({
            $or: [{ email: loginId }, { roleId: loginId }]
        });

        if (!user) {
            return res.status(400).json({ message: "User not found" });
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(400).json({ message: "Invalid password" });
        }

        const token = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({
            message: "Login successful",
            token,
            role: user.role,
            name: user.name
        });

    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// ================= START SERVER =================

app.listen(5000, () => {
    console.log("Server running on port 5000");
});