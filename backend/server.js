import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";

dotenv.config();

mongoose.connect(process.env.MONGO).then(() => {
  console.log("MongoDB is connected");
});

const app = express();
app.use(express.json());

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true,
    minlength: 5,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: function (v) {
        return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(v);
      },
      message: "Please enter a valid email",
    },
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
});

const noteSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200,
  },
  content: {
    type: String,
    required: true,
    trim: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

// Compile schemas into models
const User = mongoose.model("User", userSchema);
const Note = mongoose.model("Note", noteSchema);

const JWT_SECRET = process.env.JWT_SECRET;

// User Registration
app.post(
  "/register",
  [
    body("username").isLength({ min: 5 }),
    body("email").isEmail(),
    body("password").isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, email, password } = req.body;

      let user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ msg: "User already exists" });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      user = new User({
        username,
        email,
        password: hashedPassword,
      });

      await user.save();

      const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
        expiresIn: "1h",
      });

      res.status(201).json({ token });
    } catch (error) {
      res.status(500).send("Server error");
    }
  }
);

// User Authentication
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: "Invalid Credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid Credentials" });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (error) {
    res.status(500).send("Server error");
  }
});

// Middleware for authentication
const authenticate = (req, res, next) => {
  const token = req.header("x-auth-token");

  if (!token) {
    return res.status(401).json({ msg: "No token, authorization denied" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Token is not valid" });
  }
};



app.get("/getAllNotes", authenticate, async (req, res) => {
  try {
    const userId = req.user.userId;
    const notes = await Note.find({ userId });
    res.status(200).json(notes);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/deleteNote/:noteId", authenticate, async (req, res) => {
  try {
    const { noteId } = req.params;
    const userId = req.user.userId;

    const note = await Note.findOneAndDelete({ _id: noteId, userId });
    if (!note) {
      return res.status(404).json({ msg: `Note with ID ${noteId} not found.` });
    }
    res
      .status(200)
      .json({ msg: `Document with ID ${noteId} properly deleted.` });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.patch("/editNote/:noteId", authenticate, async (req, res) => {
  try {
    const { noteId } = req.params;
    const userId = req.user.userId;
    const { title, content } = req.body;
    const update = {};

    if (title) update.title = title;
    if (content) update.content = content;

    const note = await Note.findOneAndUpdate({ _id: noteId, userId }, update, {
      new: true,
    });

    if (!note) {
      return res.status(404).json({ msg: `Note with ID ${noteId} not found.` });
    }
    res.status(200).json(note);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(4000, () => {
  console.log("Server is running on port 4000");
});
