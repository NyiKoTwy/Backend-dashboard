import express from "express";
import cors from "cors";
import axios from "axios";
import fs from "fs";
import multer from "multer";
import dotenv from "dotenv";
import pg from "pg";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || "mySuperSecretKey123"; // Ensures consistent secret
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;
// Store insights per user instead of globally
const userInsights = new Map(); // Map user IDs to their insights data
const isLocal = process.env.DB_HOST === "localhost";
const isProduction = process.env.NODE_ENV === "production";

// Update CORS to allow your Netlify domain
app.use(cors({
    origin: ["https://dashboardwithnykotwy.netlify.app", "http://localhost:3000"],
    methods: "GET,POST,PUT,DELETE",
    credentials: true // Allow cookies in cross-origin requests
}));

const db = new pg.Client({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: isLocal ? false : { rejectUnauthorized: false }   
});

db.connect()
    .then(() => console.log(" Connected to PostgreSQL Database"))
    .catch(err => console.error(" Database Connection Error:", err));

const API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent";
const API_KEY = process.env.API_KEY;

const headers = { "Content-Type": "application/json" };

if (!fs.existsSync("uploads")) {
    fs.mkdirSync("uploads");
}

const upload = multer({ dest: "uploads/" });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Remove static file serving since we're not serving HTML from backend
// app.use(express.static(path.join(__dirname, "public")));

const validTokens = new Set(); // Store active tokens in memory

const generateToken = (user) => {
    const access_token = jwt.sign({ username: user.name, id: user.id }, JWT_SECRET, { expiresIn: "1h" });  
    validTokens.add(access_token); // Track issued tokens
    return access_token;
};

const validateToken = (req, res, next) => {
    const access_token = req.cookies["access-token"];
    console.log("Token received:", access_token);
    
    if (!access_token || !validTokens.has(access_token)) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    
    try {
        const decoded = jwt.verify(access_token, JWT_SECRET);
        if (decoded) {
            req.authenticated = true;
            req.userId = decoded.id; // Store the user ID for later use
            return next();
        }
    } catch (err) {
        console.error("Token validation error:", err);
        return res.status(401).json({ message: "Unauthorized" });
    }
};

// Invalidate all tokens when the server restarts
const clearTokensOnRestart = () => {
    validTokens.clear();
    console.log(" All tokens invalidated due to server restart.");
};
clearTokensOnRestart();

const generateInsightPrompt = (year, month, data = null) => {
    return {
        contents: [{
            parts: [{
                text: `
Analyze the booking data for ${year}-${month} and generate a single JSON object:
{
  "date": "${year}-${month}",
  "totalArrivals": <total arrivals>,
  "arrivalPercentage": <arrival percentage>,
  "memberArrivals": <total member arrivals>,
  "generalGuestArrivals": <total general guest arrivals>,
  "departuresToday": <total departures>,
  "occupancyRate": <average occupancy rate>,
  "ADR": <average daily rate>,
  "guestBirthdays": [ { "name": "John Doe", "birthday": "YYYY-MM-DD" } ],
  "ageGroupSegmentation": { "child": <total child count>, "adult": <total adult count>, "senior": <total senior count> },
  "canceledBookings": { "count": <total cancellations>, "percentage": <cancellation percentage> },
  "frequentUnits": [ { "unitId": "A101", "bookings": <most frequent bookings count> } ],
  "monthlyIncome": <total income for the selected month>,
  "yearlyIncome": <total income for the selected year>
}
${data ? `\nBooking Data:\n${data}` : ''}
Return only raw JSON.
                `
            }]
        }]
    };
};

// API health check route
app.get("/", (req, res) => {
    res.json({ 
        status: "API is running",
        message: "Backend API is operational"
    });
});

// API test route
app.get("/api/test", (req, res) => {
    res.json({ message: "API is working!" });
});

// File upload route
app.post("/upload", validateToken, upload.single("file"), async (req, res) => {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });

    try {
        const data = fs.readFileSync(req.file.path, "utf8");
        fs.unlinkSync(req.file.path); 

        const insightPrompt = generateInsightPrompt("2024", "02", data);
        const response = await axios.post(`${API_URL}?key=${API_KEY}`, insightPrompt, { headers });

        let insightsText = response.data.candidates[0].content.parts[0].text;
        const insights = JSON.parse(insightsText.replace(/```json|```/g, "").trim());
        
        // Store insights for this specific user
        userInsights.set(req.userId, insights);
        console.log(` Insights processed for user ${req.userId}:`, insights);
        res.json({ message: "Processing completed!", insights });

    } catch (err) {
        console.error(" Error processing request:", err);
        res.status(500).json({ message: "Error processing request." });
    }
});

// Get insights route
app.get("/api/insights", validateToken, (req, res) => {
    const insights = userInsights.get(req.userId);
    
    if (insights) {
        res.json(insights);
    } else {
        res.status(404).json({ message: "No insights available. Please upload a file first." });
    }
});

// Update insights route
app.post("/insights", validateToken, async (req, res) => {
    const { year, month } = req.body;

    if (!year || !month) {
        return res.status(400).json({ message: "Year and month are required." });
    }

    try {
        const insightPrompt = generateInsightPrompt(year, month);
        const response = await axios.post(`${API_URL}?key=${API_KEY}`, insightPrompt, { headers });

        let insightsText = response.data.candidates[0].content.parts[0].text;
        const insights = JSON.parse(insightsText.replace(/```json|```/g, "").trim());
        
        // Store insights for this specific user
        userInsights.set(req.userId, insights);

        console.log(` Insights updated for user ${req.userId}:`, insights);
        res.json({ message: "Insights updated!", insights });
    } catch (error) {
        console.error(" Error fetching insights:", error);
        res.status(500).json({ message: "Error fetching insights." });
    }
});

// Login route
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await db.query("SELECT * FROM user_id WHERE name = $1", [username]);

        if (result.rows.length === 0) {
            return res.status(401).json({ message: "User not found" });
        }

        const user = result.rows[0];
        console.log("User found:", user.name);
        
        if (user.password === password) {
            const token = generateToken(user);
            res.cookie("access-token", token, { 
                maxAge: 900000, 
                httpOnly: true, 
                secure: true, // Always use secure in production
                sameSite: "None" // Required for cross-site cookies
            });
            res.json({ message: "Login successful", redirect: "/dashboard" });
        } else {
            res.status(401).json({ message: "Incorrect password or username" });
        }
    } catch (err) {
        console.error(" Error fetching password:", err);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

// Authentication status check for dashboard
app.get("/dashboard", validateToken, (req, res) => {
    res.json({ authenticated: true, userId: req.userId });
});

// Additional route for auth status check
app.get("/api/auth-status", validateToken, (req, res) => {
    res.json({ 
        authenticated: true, 
        userId: req.userId,
        username: req.username 
    });
});

// Logout route
app.post("/logout", (req, res) => {
    const token = req.cookies["access-token"];
    if (token) {
        validTokens.delete(token);
    }
    res.clearCookie("access-token");
    res.json({ message: "Logged out successfully" });
});

app.listen(port, () => {
    console.log(` Server is running on port ${port}`);
});
