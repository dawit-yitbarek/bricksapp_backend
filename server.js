import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import nodemailer from "nodemailer";
import passport from "passport";
import cron from 'node-cron'
import GoogleStrategy from "passport-google-oauth20";
import "dotenv/config";
import cors from 'cors';
import bcrypt from "bcrypt";
import jwt from 'jsonwebtoken';
import pkg from "pg";
const { Pool } = pkg;


const app = express();
const port = process.env.PORT;
const saltRounds = 10;
const telegramBotToken = process.env.TELEGRAM_BOT_TOKEN;

async function getVerificationCode(email, verificationCode) {
  try {
    const mailOptions = {
      from: `"Bricks App Verification" ${process.env.EMAIL_USER}`,
      to: email,
      subject: 'Your Verification Code for Bricks App',
      text: `Hello,\n\nYour verification code is: ${verificationCode}\nThis code is valid for 10 minutes.\n\nIf you did not request this, you can safely ignore this email.\n\nThanks,\nBricks App Team`,
      html: `
        <div style="font-family: Arial, sans-serif; color: #333; font-size: 16px; line-height: 1.6;">
          <p>Hello,</p>
          <p>Here is your verification code for <strong>Bricks App</strong>:</p>
          <p style="font-size: 24px; font-weight: bold; color: #2d89ef; letter-spacing: 2px;">${verificationCode}</p>
          <p>This code is valid for <strong>10 minutes</strong>.</p>
          <hr style="border: none; border-top: 1px solid #ccc;" />
          <p style="font-size: 14px; color: #777;">If you did not request this code, you can safely ignore this email.</p>
          <p style="margin-top: 20px;">Thanks,<br/><strong>Bricks App Team</strong></p>
          <p style="font-size: 12px; color: #999; margin-top: 40px;">
            This email was sent by Bricks App. If you have any questions, contact us at brickstomoon@gmail.com
          </p>
        </div>
      `,
    };

    await new Promise((resolve, reject) => {
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) return reject(error);
        resolve(info);
      });
    });

    return { success: true }
  } catch (error) {
    console.error("Error in getVerificationCode:", error);
    return { success: false }
  }
}

console.log("DATABASE_URL:", process.env.DATABASE_URL);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});


pool.connect((err) => {
  if (err) {
    console.error('Failed to connect to the database:', err);
  } else {
    console.log('Database connection successful!');
  }
});


// 🧹 Clean expired pending_verifications every 10 minutes
cron.schedule('*/10 * * * *', async () => {
  try {
    await pool.query(`
      DELETE FROM pending_verifications
      WHERE created_at < NOW() - INTERVAL '10 minutes'
    `);
    console.log("✅ Expired pending_verifications cleaned up");
  } catch (err) {
    console.error("❌ Cleanup error: ", err);
  }
});


app.use(cors({
  origin: ['https://bricksapp-frontend.onrender.com'],
  credentials: true
}));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(passport.initialize());
app.use(cookieParser());


const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});


function verifyTelegrmAuth(data) {
  const authData = URLSearchParams(data);
  const hash = authData.get("hash");
  authData.delete("hash");

  const sortedData = [...authData].sort().map(([Key, val]) => `${Key}=${val}`).join("\n");
  const secretKey = crypto.createHmac("sha256").update(telegramBotToken).digest();
  const expectedHash = crypto.createHmac("sha256", secretKey).update(sortedData).digest("hex");

  return hash === expectedHash;
}


//refresh route
app.post("/refresh", async (req, res) => {
  const token = req.cookies.refreshToken;
  const access = req.headers['authorization']?.split(' ')[1];
  console.log("accessToken from refresh route", access)


  // Check if refresh token is provided
  if (!token) return res.json({ success: false, message: "No refresh token provided" });

  try {
    // Verify the refresh token
    const decoded = jwt.verify(token, process.env.REFRESH_SECRET);

    if (access) {
      try {
        console.log("access token found")
        // Verify if access token is still valid
        jwt.verify(access, process.env.ACCESS_SECRET);
        return res.json({ message: "Access token still valid", success: true, accessToken: access });
      } catch (error) {
        // If access token expired, generate a new one using refresh token
        if (error.name === 'TokenExpiredError') {
          const accessToken = jwt.sign({ id: decoded.id }, process.env.ACCESS_SECRET, { expiresIn: "15m" });
          return res.json({ accessToken, success: true });
        }
        // Handle invalid access token other than expiration
        res.clearCookie("refreshToken", { httpOnly: true, secure: true, sameSite: "Strict" });
        console.log("cookie cleared")
        return res.json({ message: "Invalid access token", success: false });
      }
    } else {
      console.log("access token didn't found")
      // If no access token is provided, generate new one using refresh token
      const accessToken = jwt.sign({ id: decoded.id }, process.env.ACCESS_SECRET, { expiresIn: "15m" });
      return res.json({ accessToken, success: true });
    }

  } catch (error) {
    console.log("Error on refresh route", error);
    return res.json({ success: false, message: "Server error" });
  }
});

//logout route
app.post("/logout", async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(204); // already logged out
  res.clearCookie("refreshToken", { httpOnly: true, secure: true, sameSite: "Strict" });
  res.sendStatus(204);
});


//signin route
app.post("/signin", async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const selectUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (selectUser.rows.length === 0) {
      console.log("User not found with this email");
      return res.json({ success: false, message: "User not found with this email" });
    }
    const user = selectUser.rows[0];


    if (user.authenticator === "google") {
      console.log("authentication method is google");
      return res.json({ success: false, message: "you login with this email using google before. please login using google again" });
    }

    const storedHashedPassword = user.password;

    const valid = await bcrypt.compare(password, storedHashedPassword); // Await bcrypt comparison

    if (!valid) {
      console.log("Incorrect password");
      return res.json({ success: false, message: "Incorrect password" });
    }

    // ✅ Generate tokens
    const accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_SECRET, { expiresIn: "150d" });

    // ✅ Send refresh token in HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 1000 * 60 * 60 * 24 * 30 * 5, // 5 months
    });

    return res.json({
      success: true,
      accessToken
    });

  } catch (err) {
    console.error("Error during authentication:", err);
    return res.json({ success: false, message: "Server error" });
  }
});




app.get("/dashboard", async (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.json({ message: "Unauthorized", success: false });
  }

  try {
    console.log("accessToken from dashboard route", token)
    const decoded = jwt.verify(token.replace("Bearer ", ""), process.env.ACCESS_SECRET);
    const user = await pool.query("SELECT * FROM users WHERE id = $1", [decoded.id]);

    if (user.rows.length === 0) {
      return res.json({ message: "User not found", success: false });
    }
    const result = user.rows[0];
    result.success = true;

    res.json(result);

  } catch (err) {
    console.error("Error verifying token:", err);
    res.json({ message: "Invalid token", success: false });
  }
});



//register route
app.post("/register", async (req, res, next) => {
  const { email, password } = req.body;

  try {

    const existing = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existing.rows.length > 0) {
      return res.json({ success: false, message: "User already registered, please login" });
    }

    const hash = await bcrypt.hash(password, saltRounds);
    const code = String(Math.floor(Math.random() * 999999) + 1).padStart(6, '0');

    await pool.query(`
      INSERT INTO pending_verifications (email, hashed_password, code)
      VALUES ($1, $2, $3)
      ON CONFLICT (email) DO UPDATE SET hashed_password = $2, code = $3, created_at = NOW()
    `, [email, hash, code]);

    const verificationCode = await getVerificationCode(email, code); // a separate function for sending email
    if (!verificationCode.success) {
      return res.json({ success: false, message: "failed to send a verification code" });
    }

    res.json({ success: true, message: "Verification code sent to your email." });
  } catch (error) {
    console.error("Error occurred on registering user ", error);
    res.json({ success: false, message: "Registration failed" });
  }
});








//connect wallet route
app.post("/connect-wallet", async (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) return res.json({ message: "Unauthorized" }); // Check if user is authenticated
  const { address } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.REFRESH_SECRET);
    const insertAddress = await pool.query("UPDATE wallet SET address = $1 WHERE user_id = $2 RETURNING *", [address, decoded.id]);
    console.log(insertAddress.rows[0]);
    res.json(insertAddress.rows[0]);
  } catch (error) {
    console.error("error on connecting wallet ", error);
    res.json({ message: "Failed to connect wallet" });
  }
});


//get wallet route
app.get("/get-wallet", async (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) return res.json({ message: "Unauthorized" }); // Check if user is authenticated
  try {
    const decoded = jwt.verify(token, process.env.REFRESH_SECRET);
    const getWallet = await pool.query("SELECT * FROM wallet WHERE user_id = $1", [decoded.id]);
    const selectedAddress = getWallet.rows[0];
    if (!selectedAddress) {
      res.json({ address: "no address" });
    }

    res.json({ address: selectedAddress.address || null });
  } catch (error) {
    console.error("error on getting wallet ", error);
    res.status(500).json({ message: "Failed to get wallet address" });
  }
});


//disconnect wallet route
app.post("/disconnect-wallet", async (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) return res.status(401).json({ message: "Unauthorized" }); // Check if user is authenticated
  try {
    const decoded = jwt.verify(token, process.env.REFRESH_SECRET);
    await pool.query("UPDATE wallet SET address = $1 WHERE user_id = $2 RETURNING *", [null, decoded.id]);
    res.json({ success: true });
  } catch (error) {
    console.error("error on disconnecting wallet ", error); 
    res.json({ message: "Failed to disconnect wallet", success: false });
   }
});



passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://bricksapp-backend.onrender.com/auth/google/dashboard",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [
          profile.emails[0].value

        ]);

        let user;

        if (result.rows.length === 0) {
          const newUser = await pool.query(
            "INSERT INTO users (email, password, authenticator, is_verified) VALUES ($1, $2, $3, $4) RETURNING *",
            [profile.emails[0].value, null, "google", true]
          );
          await pool.query(`
            INSERT INTO wallet (address, user_id) VALUES ($1, $2)
          `, [null, newUser.rows[0].id]);
           user = newUser.rows[0]
        } else {
           user = result.rows[0];
        }

        // Generate JWT token
        const accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_SECRET, { expiresIn: "15m" });

        return cb(null, { user, accessToken });
      } catch (err) {
        return cb(err);
      }
    }
  )
);

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get("/auth/google/dashboard", passport.authenticate("google", { 
  session: false,
  failureRedirect: "https://bricksapp-frontend.onrender.com/signin",
 }), (req, res) => {
 
  const { user } = req.user;

  const refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_SECRET, { expiresIn: "150d" });

  // ✅ Send refresh token in HTTP-only cookie
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 1000 * 60 * 60 * 24 * 30 * 5, // 5 months
  });

  res.redirect("https://bricksapp-frontend.onrender.com")
});



app.post("/verify-email", async (req, res) => {
  const { email, code } = req.body;
  

  try {
    const result = await pool.query(`
      SELECT * FROM pending_verifications
      WHERE email = $1 AND code = $2 AND created_at > NOW() - INTERVAL '10 minutes'
    `, [email, code]);

    if (result.rows.length === 0) {
      return res.json({ success: false, message: "Invalid or expired verification token" });
    }
    const { hashed_password } = result.rows[0];


    const user = await pool.query(`
      INSERT INTO users (email, password, is_verified, authenticator)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `, [email, hashed_password, true, 'email']);

    await pool.query(`
      INSERT INTO wallet (address, user_id) VALUES ($1, $2)
    `, [null, user.rows[0].id]);

    await pool.query("DELETE FROM pending_verifications WHERE email = $1", [email]);

    const refreshToken = jwt.sign({ id: user.rows[0].id }, process.env.REFRESH_SECRET, { expiresIn: "150d" });
    const accessToken = jwt.sign({ id: user.rows[0].id }, process.env.ACCESS_SECRET, { expiresIn: "15m" });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 1000 * 60 * 60 * 24 * 30 * 5, // 5 months
    });

    res.json({
      success: true,
      accessToken,
      message: "Email verified successfully",
    });



  } catch (error) {
    console.error("Error verifying email:", error);
    res.json({ success: false, message: "Failed to verify email" });
  }
});




// app.post("/auth/telegram", async (req, res, next) => {
//   console.log("Telegram Authentication Request Received");
//   const data = req.body;
//   console.log("Received Data:", data || null);

//   if (!verifyTelegrmAuth(data)) {
//     return res.json({ success: false, message: "Invalid telegram data" });
//   }

//   const telegramId = data.id;

//   try {
//     const user = await pool.query("SELECT * FROM users WHERE telegram_id = $1", [telegramId]);

//     if (user.rows.length === 0) {
//       const newUser = await pool.query(
//         "INSERT INTO users (email, is_verified, authenticator, telegram_id) VALUES ($1, $2, $3, $4) RETURNING *",
//         [null, true, "telegram", telegramId]
//       );

//       req.login(newUser.rows[0], (err) => {
//         if (err) {
//           return next(err);
//         }
//         res.json({ success: true });
//       });
//     } else {
//       req.login(user.rows[0], (err) => {
//         if (err) {
//           return next(err);
//         }
//         res.json({ success: true });
//       });
//     }
//   } catch (error) {
//     console.log("Error on login with Telegram:", error);
//     res.json({ success: false, message: "Authorization failed, please try again" });
//   }
// });







// It's monitored by UptimeRobot, which sends a request every 5 minutes.
app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

// Error-handling middleware (must be defined after routes)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server is running on port ${port}`);
});