import express from "express";
import mysql from "mysql";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "1234",
    database: "universitydb"
});

app.use(express.json());

app.use(cors({ origin: "http://localhost:3000", credentials: true }));


const SECRET_KEY = process.env.JWT_SECRET || "your-secret-key"; // 🔒 Store securely in .env

// ✅ Middleware to Verify Token
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Access Denied! No token provided." });

    try {
        const verified = jwt.verify(token, SECRET_KEY);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ message: "Invalid token" });
    }
};

// ✅ API: Login
app.post("/api/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
    }

    const q = "SELECT user_id, user_name, password_hash, role FROM users WHERE user_email = ?";
    db.query(q, [email], async (err, data) => {
        if (err) return res.status(500).json({ message: "Database error", error: err });

        if (data.length === 0) return res.status(401).json({ message: "User not found" });

        const user = data[0];

        // 🔒 Compare hashed password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ message: "Invalid password" });

        // ✅ Generate JWT Token (Make sure role is included)
        const token = jwt.sign(
            { user_id: user.user_id, role: user.role }, // ✅ Include role
            SECRET_KEY,
            { expiresIn: "1h" }
        );

        console.log("✅ Login successful! Sending token:", token); // Debugging
        res.json({ message: "Login successful!", token, user }); // ✅ Send token to frontend
    });
});


// ✅ API: Register User (HOD/Admin)
app.post("/api/register", verifyToken, async (req, res) => {
    const { username, email, password, role, research_area } = req.body;

    // ✅ Extract `dept_id` from the logged-in user (HOD/Admin)
    const dept_id = req.user.dept_id;
    if (!username || !email || !password || !role || !dept_id) {
        return res.status(400).json({ message: "All fields are required" });
    }

    const user_id = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);

    const q = "INSERT INTO users (user_id, user_name, user_email, password_hash, role, dept_id) VALUES (?, ?, ?, ?, ?, ?)";
    db.query(q, [user_id, username, email, hashedPassword, role, dept_id], (err, result) => {
        if (err) return res.status(500).json({ message: "Database error", error: err });

        // ✅ Insert research area only for professors
        if (role === "professor" && research_area) {
            const q2 = "UPDATE professors SET research_area = ? WHERE user_id = ?";
            db.query(q2, [research_area, user_id], (err) => {
                if (err) return res.status(500).json({ message: "Error updating research area", error: err });
            });
        }

        res.json({ message: "User registered successfully!", user_id });
    });
});


// ✅ API: Update User (HOD/Admin)
app.put("/api/update/:user_id", verifyToken, (req, res) => {
    const { user_id } = req.params;
    const { username, email, role } = req.body;

    const q = "UPDATE users SET user_name = ?, user_email = ?, role = ? WHERE user_id = ?";
    db.query(q, [username, email, role, user_id], (err, result) => {
        if (err) return res.status(500).json({ message: "Database error", error: err });

        res.json({ message: "User updated successfully!" });
    });
});

// ✅ API: Delete User (HOD/Admin)
app.delete("/api/delete/:user_id", verifyToken, (req, res) => {
    const { user_id } = req.params;

    const q = "DELETE FROM users WHERE user_id = ?";
    db.query(q, [user_id], (err, result) => {
        if (err) return res.status(500).json({ message: "Database error", error: err });

        res.json({ message: "User deleted successfully!" });
    });
});

// ✅ API: Fetch Professors (Super Admin View)
app.get("/api/professors", verifyToken, (req, res) => {
    const q = `SELECT p.professor_id, u.user_id, u.user_name, u.user_email, u.role, p.dept_id, p.faculty_id
               FROM professors p JOIN users u ON p.user_id = u.user_id WHERE u.role = 'professor'`;

    db.query(q, (err, data) => {
        if (err) return res.status(500).json({ message: "Database error", error: err });

        res.json(data);
    });
});

// ✅ API: Assign HOD (Super Admin)
app.put("/api/superadmin/assign-hod", verifyToken, (req, res) => {
    const { user_id } = req.body;

    if (!user_id) return res.status(400).json({ message: "User ID is required" });

    const checkQuery = `SELECT u.user_id FROM users u JOIN professors p ON u.user_id = p.user_id
                        WHERE u.user_id = ? AND u.role = 'professor'`;

    db.query(checkQuery, [user_id], (err, data) => {
        if (err) return res.status(500).json({ message: "Database error", error: err });

        if (data.length === 0) return res.status(400).json({ message: "User is not a professor or does not exist" });

        const updateQuery = "UPDATE users SET role = 'hod' WHERE user_id = ?";
        db.query(updateQuery, [user_id], (err, result) => {
            if (err) return res.status(500).json({ message: "Database error", error: err });

            res.json({ message: "User assigned as HOD!" });
        });
    });
});

// ✅ API: Change Password
app.put("/api/users/change-password", verifyToken, async (req, res) => {
    const { user_id, currentPassword, newPassword } = req.body;

    if (!user_id || !currentPassword || !newPassword) return res.status(400).json({ message: "All fields are required" });

    const q = "SELECT password_hash FROM users WHERE user_id = ?";
    db.query(q, [user_id], async (err, data) => {
        if (err) return res.status(500).json({ message: "Database error", error: err });

        if (data.length === 0) return res.status(404).json({ message: "User not found" });

        const isMatch = await bcrypt.compare(currentPassword, data[0].password_hash);
        if (!isMatch) return res.status(401).json({ message: "Current password is incorrect" });

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        const updateQuery = "UPDATE users SET password_hash = ? WHERE user_id = ?";

        db.query(updateQuery, [hashedNewPassword, user_id], (err, result) => {
            if (err) return res.status(500).json({ message: "Database error", error: err });

            res.json({ message: "Password updated successfully!" });
        });
    });
});

// ✅ API: Fetch Rooms for Professors
app.get("/api/rooms/:dept_id", verifyToken, (req, res) => {
    const { dept_id } = req.params;
    if (!dept_id) return res.status(400).json({ error: "Invalid department ID" });

    const q = "SELECT * FROM rooms WHERE dept_id = ?";
    db.query(q, [dept_id], (err, data) => {
        if (err) return res.status(500).json({ error: "Database query failed" });

        res.json(data);
    });
});


app.get("/api/professors", (req, res) => {
     const q = `
         SELECT p.professor_id, u.user_id, u.user_name, u.user_email, u.role, p.dept_id, p.faculty_id
         FROM professors p
         JOIN users u ON p.user_id = u.user_id
         WHERE u.role = 'professor'
     `;

     db.query(q, (err, data) => {
         if (err) {
             console.error("❌ Database error:", err);
             return res.status(500).json({ message: "Database error", error: err });
         }

         console.log("✅ Professors API Response:", data);
         res.json(data);
     });
 });

// // ✅ API to Fetch Faculties
 app.get("/api/faculties", (req, res) => {
     const q = "SELECT faculty_id, f_name FROM faculties";
     db.query(q, (err, data) => {
         if (err) {
             console.error("❌ Error fetching faculties:", err);
             return res.status(500).json({ message: "Database error", error: err });
         }
         res.json(data);
     });
 });

// // ✅ API to Fetch Departments Based on Selected Faculty
 app.get("/api/departments/:faculty_id", (req, res) => {
     const { faculty_id } = req.params;

     const q = "SELECT dept_id, dept_name FROM departments WHERE faculty_id = ?";
     db.query(q, [faculty_id], (err, data) => {
         if (err) {
             console.error("❌ Error fetching departments:", err);
             return res.status(500).json({ message: "Database error", error: err });
         }
         res.json(data);
     });
 });

app.get('/rooms/:dept_id', (req, res) => {
     const department_id = req.params.dept_id;

     if (!department_id) {
         return res.status(400).json({ error: "Invalid department ID" });
     }

     const q = "SELECT * FROM rooms WHERE dept_id = ?";

     db.query(q, [department_id], (err, data) => {
         if (err) {
             console.error("❌ Error fetching rooms:", err);
             return res.status(500).json({ error: "Database query failed" });
         }
         if (data.length === 0) {
             return res.status(404).json({ message: "No rooms found for this department" });
         }
         console.log("✅ Rooms API Response:", data);
         return res.json(data);
     });
 });

 app.get("/api/users", (req, res) => {
    const q = "SELECT user_id, user_name, user_email, role FROM users";
    db.query(q, (err, data) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ message: "Database error", error: err });
        }
        res.json(data);
    });
});

// ✅ API: Register User (HOD/Admin)
app.post("/api/register", async (req, res) => {
    try {
        // 🔍 Extract and verify the token
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ message: "Access Denied! No token provided." });

        let decoded;
        try {
            decoded = jwt.verify(token, SECRET_KEY);
        } catch (err) {
            return res.status(403).json({ message: "Invalid token" });
        }

        // ✅ Extract the department from the logged-in user
        const dept_id = decoded.dept_id;
        if (!dept_id) {
            return res.status(403).json({ message: "Unauthorized: Missing department info" });
        }

        // 🔍 Extract user details from request body
        const { username, email, password, role, research_area } = req.body;
        if (!username || !email || !password || !role) {
            return res.status(400).json({ message: "All fields are required except research area (optional for professors)" });
        }

        // 🔐 Generate UUID for new user & hash password
        const user_id = uuidv4();
        const hashedPassword = await bcrypt.hash(password, 10);

        // 🔹 Insert new user into the `users` table
        const insertUserQuery = "INSERT INTO users (user_id, user_name, user_email, password_hash, role, dept_id) VALUES (?, ?, ?, ?, ?, ?)";
        db.query(insertUserQuery, [user_id, username, email, hashedPassword, role, dept_id], (err, result) => {
            if (err) {
                console.error("❌ Error registering user:", err);
                return res.status(500).json({ message: "Database error", error: err });
            }

            // 🔹 If role is "professor", insert research area
            if (role === "professor" && research_area) {
                const insertProfessorQuery = "INSERT INTO professors (user_id, research_area, dept_id) VALUES (?, ?, ?)";
                db.query(insertProfessorQuery, [user_id, research_area, dept_id], (err, result) => {
                    if (err) {
                        console.error("❌ Error inserting professor research area:", err);
                        return res.status(500).json({ message: "Database error while inserting professor data", error: err });
                    }
                });
            }

            console.log("✅ User registered successfully:", { user_id, username, role, dept_id });
            res.json({ message: "User registered successfully!", user_id });
        });

    } catch (error) {
        console.error("❌ Error registering user:", error);
        res.status(500).json({ message: "Internal server error", error });
    }
});



// ✅ Start Backend Server
app.listen(8800, () => {
    console.log("✅ Backend running on port 8800!");
});
