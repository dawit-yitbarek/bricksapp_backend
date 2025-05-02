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
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import pkg from "pg";
import { Connection } from "@solana/web3.js";
import rateLimit from 'express-rate-limit';
const { Pool } = pkg;


const app = express();
const port = process.env.PORT;
const saltRounds = 10;

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


// database configuration
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false,
    },
  });
  
  console.log("DATABASE_URL:", process.env.DATABASE_URL);


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

// update daily_reward every day at midnight
cron.schedule('0 0 * * *', async () => {
  try {

    // 1. Reset users who did NOT claim today -> reset their streak to 1
    await pool.query(`
        UPDATE daily_reward
        SET streak = 1, claimed = false
        WHERE claimed = false AND streak > 1
      `);

    // 2. Update users who claimed today -> add to their streak
    await pool.query(`
        UPDATE daily_reward
        SET streak = streak + 1, claimed = false
        WHERE daily_reward.claimed = true
      `);

    console.log("✅ daily_reward table updated");
  } catch (err) {
    console.error("❌ Updating error: ", err);
  }
}, {
  timezone: 'UTC'
});


app.use(cors({
  origin: [process.env.FRONTEND_URL],
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

const verifyAccessToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ success: false, message: "Access token missing" });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_SECRET);
    req.user = decoded; // attach decoded data to request object
    next();
  } catch (err) {
    return res.status(403).json({ success: false, message: "Access token invalid or expired" });
  }
};

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  handler: (req, res) => {
    console.log(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      success: false,
      message: 'Too many registration attempts. Please try again later.'
    });
  },
  standardHeaders: true,
  legacyHeaders: false,
});



//refresh route
app.post("/refresh", async (req, res) => {
  const refreshtoken = req.cookies.refreshToken;

  // Check if refresh token is provided
  if (!refreshtoken) return res.json({ success: false, message: "No refresh token provided" });
  try {
    // Verify the refresh token
    const decoded = jwt.verify(refreshtoken, process.env.REFRESH_SECRET);
    const newAccessToken = jwt.sign({ id: decoded.id }, process.env.ACCESS_SECRET, { expiresIn: "15m" });

    return res.json({ newAccessToken, success: true });
  } catch (error) {
    console.log("Error on refresh route", error);
    res.clearCookie("refreshToken", { httpOnly: true, secure: true, sameSite: "None" });
    return res.json({ success: false, message: "Server error" });
  }
});



//logout route
app.post("/logout", async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(204); // already logged out
  res.clearCookie("refreshToken", { httpOnly: true, secure: true, sameSite: "None" });
  res.sendStatus(204);
});


//signin route
app.post("/signin", async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const selectUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);


    if (selectUser.rowCount === 0) {
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




app.get("/dashboard", verifyAccessToken, async (req, res) => {
  const userId = req.user?.id

  try {
    const user = await pool.query(
      `SELECT users.*, daily_reward.claimed, daily_reward.streak
       FROM users
       JOIN daily_reward ON users.id = daily_reward.user_id
       WHERE users.id = $1`,
      [userId]
    );

    if (user.rowCount === 0) {
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


app.post("/register", registerLimiter , async (req, res) => {
  const { email, password, referralCode } = req.body;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const existing = await client.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existing.rowCount > 0) {
      await client.query("ROLLBACK");
      return res.json({ success: false, message: "User already registered, please login" });
    }

    const hash = await bcrypt.hash(password, saltRounds);
    const code = String(Math.floor(Math.random() * 999999) + 1).padStart(6, '0');

    await client.query(`
      INSERT INTO pending_verifications (email, hashed_password, code, invited_by)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (email) DO UPDATE SET hashed_password = $2, code = $3, created_at = NOW()
    `, [email, hash, code, referralCode]);

    const verificationCode = await getVerificationCode(email, code); // Send email code
    if (!verificationCode.success) {
      await client.query("ROLLBACK");
      return res.json({ success: false, message: "Failed to send verification code" });
    }

    await client.query("COMMIT");
    res.json({ success: true, message: "Verification code sent to your email." });

  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Error occurred on registering user:", error);
    res.json({ success: false, message: "Registration failed" });
  } finally {
    client.release();
  }
});



//connect wallet route
app.post("/connect-wallet", verifyAccessToken, async (req, res) => {
  const userId = req.user?.id

  const { address, walletName } = req.body;
  try {

    const existingWallet = await pool.query(
      "SELECT 1 FROM wallet WHERE address = $1 AND user_id != $2",
      [address, userId]
    );

    const userWallet = await pool.query(
      "SELECT address FROM wallet WHERE user_id = $1",
      [userId]
    );

    // Check if user already has a connected wallet
    if (userWallet.rows[0]?.address) {
      if (userWallet.rows[0]?.address !== address) {
        return res.json({ success: false, message: "You have already connected a wallet. Disconnect it to connect another wallet" });
      };
    };

    // Check if the new wallet address is already connected to another user
    if (existingWallet.rowCount > 0) {
      return res.json({ success: false, message: "This wallet address is already connected to another account" });
    }


    const insertAddress = await pool.query("UPDATE wallet SET address = $1, wallet_name = $2 WHERE user_id = $3 RETURNING *", [address, walletName, userId]);
    res.json({ insertedAddress: insertAddress.rows[0], success: true });
  } catch (error) {
    console.error("error on connecting wallet ", error);
    res.json({ success: false, message: "Failed to connect wallet" });
  }
});


//disconnect wallet route
app.post("/disconnect-wallet", verifyAccessToken, async (req, res) => {
  const userId = req.user?.id

  try {
    await pool.query("UPDATE wallet SET address = $1, wallet_name = $2 WHERE user_id = $3 RETURNING *", [null, null, userId]);
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
      callbackURL: `${process.env.BACKEND_URL}/auth/google/dashboard`,
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
      passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, profile, cb) => {
      try {
        const referredBy = (!req.cookies.referralCode || req.cookies.referralCode === "undefined")
          ? null
          : req.cookies.referralCode;


        const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [
          profile.emails[0].value

        ]);

        let user;

        if (existingUser.rowCount === 0) {

          const newUser = await pool.query(
            "INSERT INTO users (email, name, authenticator, invited_by) VALUES ($1, $2, $3, $4) RETURNING *",
            [profile.emails[0].value, profile.displayName, "google", referredBy]
          );
          await pool.query(`INSERT INTO wallet ( user_id ) VALUES ($1)`, [newUser.rows[0].id]);
          await pool.query("INSERT INTO daily_reward (user_id) VALUES ($1)", [newUser.rows[0].id]);
          await pool.query("INSERT INTO referral_bonus (user_id) VALUES ($1)", [newUser.rows[0].id]);
          await pool.query("UPDATE users SET referral_number = referral_number + 1, point = point + 500 WHERE referral_code = $1", [referredBy]);
    
          user = newUser.rows[0]

          const newReferralCode = nanoid(6) + user.id.toString();
          // const randomAvatar = `https://avatar.iran.liara.run/public/${Math.floor(Math.random() * 50) + 1}`;
          const randomAvatar = `https://robohash.org/${user.id}?set=set3`
          // const randomAvatar = `https://api.dicebear.com/7.x/adventurer/png?seed=${user.id}`;
          await pool.query("UPDATE users SET referral_code = $1, avatar_url = $2  WHERE id = $3", [newReferralCode, randomAvatar, user.id]);
        } else {
          user = existingUser.rows[0];
        }

        // Generate JWT token
        const accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_SECRET, { expiresIn: "15m" });
        req.res.clearCookie("referralCode", {
          httpOnly: true,
          secure: true,
          sameSite: "None",
        }); //clear referral code after registration  

        return cb(null, { user, accessToken });
      } catch (err) {
        return cb(err);
      }
    }
  )
);

app.get("/auth/google", (req, res, next) => {
  const referral = req.query.ref;
  if (referral) {
    res.cookie("referralCode", referral, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 10 * 60 * 1000,
    });
  }
  next();
}, passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/dashboard", passport.authenticate("google", {
  session: false,
  failureRedirect: `${process.env.BACKEND_URL}/signin`,
}), (req, res) => {

  const { user, accessToken } = req.user;

  const refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_SECRET, { expiresIn: "150d" });
  
  // ✅ Send refresh token in HTTP-only cookie
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 1000 * 60 * 60 * 24 * 30 * 5, // 5 months
  });

  res.cookie("accessToken", accessToken, {
    httpOnly: false, // Let frontend JS access it
    secure: true,
    sameSite: "None",
    maxAge: 15 * 60 * 1000, // 15 minutes
  });


  res.redirect(process.env.FRONTEND_URL)
});



app.post("/verify-email", async (req, res) => {
  const { email, code, name } = req.body;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(`
      SELECT * FROM pending_verifications
      WHERE email = $1 AND code = $2 AND created_at > NOW() - INTERVAL '10 minutes'
    `, [email, code]);

    if (result.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.json({ success: false, message: "Invalid or expired verification token" });
    }

    const { hashed_password, invited_by } = result.rows[0];
    const user = await client.query(`
      INSERT INTO users (email, password, name, authenticator, invited_by)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `, [email, hashed_password, name, 'email', invited_by]);

    const referralCode = nanoid(6) + user.rows[0].id.toString();
    // const randomAvatar = `https://avatar.iran.liara.run/public/${Math.floor(Math.random() * 50) + 1}`;
    const randomAvatar = `https://robohash.org/${user.rows[0].id}?set=set3`
    // const randomAvatar = `https://api.dicebear.com/7.x/adventurer/png?seed=${user.rows[0].id}`;

    await client.query("UPDATE users SET referral_code = $1, avatar_url = $2 WHERE id = $3", [referralCode, randomAvatar, user.rows[0].id]);
    await client.query("INSERT INTO wallet (address, user_id) VALUES ($1, $2)", [null, user.rows[0].id]);
    await client.query("INSERT INTO daily_reward (user_id) VALUES ($1)", [user.rows[0].id]);
    await client.query("DELETE FROM pending_verifications WHERE email = $1", [email]);
    await client.query("update users SET referral_number = referral_number + 1, point = point + 500 WHERE referral_code = $1", [invited_by]);
    await client.query("INSERT INTO referral_bonus (user_id) VALUES ($1)", [user.rows[0].id])

    await client.query("COMMIT");

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
      message: "",
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("❌ Error verifying email:", error);
    res.json({ success: false, message: "Failed to verify email" });
  } finally {
    client.release();
  }
});



app.post('/connect-telegram', verifyAccessToken, async (req, res) => {
  const userId = req.user?.id

  try {
    const { telegramData } = req.body;

    const { hash, ...data } = telegramData;
    const secret = crypto
      .createHash('sha256')
      .update(process.env.TELEGRAM_BOT_TOKEN)
      .digest();

    // Create the check string
    const checkString = Object.keys(data)
      .sort()
      .map((key) => `${key}=${data[key]}`)
      .join('\n');

    // Compute the hash
    const computedHash = crypto
      .createHmac('sha256', secret)
      .update(checkString)
      .digest('hex');

    // Verify if the computed hash matches the received hash
    if (computedHash !== hash) {
      return res.json(
        { redirect: `${process.env.FRONTEND_URL}/tasks?tgError=Invalid telegram hash` });
    }

    const userTelegramId = data.id;

    const existingUser = await pool.query(
      'SELECT * FROM users WHERE telegram_id = $1',
      [userTelegramId]
    );

    if (existingUser.rowCount > 0) {
      return res.json(
        { redirect: `${process.env.FRONTEND_URL}/tasks?tgError=This Telegram account already connected to another account` });
    }

    await pool.query(
      'UPDATE users SET telegram_id = $1 WHERE id = $2',
      [userTelegramId, userId]
    );

    res.json(
      { redirect: `${process.env.FRONTEND_URL}/tasks` }
    );

  } catch (error) {
    console.error("Telegram connection failed:", error.message);
    res.json(
      { redirect: `${process.env.FRONTEND_URL}/tasks?tgError=Failed to connect telegram account` }
    );
  }
});



app.get("/user-task", verifyAccessToken, async (req, res) => {
  const userId = req.user?.id

  try {
    const completedTasksRes = await pool.query(
      "SELECT task_id FROM completed_tasks WHERE user_id = $1",
      [userId]
    );

    const completedTaskIds = completedTasksRes.rows.map(row => row.task_id);

    // Fetch completed tasks
    let completedTasks = [];
    let incompleteTasks = [];
    if (completedTaskIds.length > 0) {
      const placeholders = completedTaskIds.map((_, i) => `$${i + 1}`).join(", ");

      const completedTasksResult = await pool.query(
        `SELECT * FROM tasks WHERE id IN (${placeholders})`,
        completedTaskIds
      );

      const incompleteTasksResult = await pool.query(
        `SELECT * FROM tasks WHERE id NOT IN (${placeholders})`,
        completedTaskIds
      );

      completedTasks = completedTasksResult;
      incompleteTasks = incompleteTasksResult;
    } else {
      // All tasks are incomplete if none are completed
      incompleteTasks = await pool.query("SELECT * FROM tasks");
    }


    res.json({
      success: true,
      completedTasks: completedTasks.rows,
      incompleteTasks: incompleteTasks.rows,
    });

  } catch (err) {
    console.error("Error verifying token:", err);
    res.json({ message: "Invalid token", success: false });
  }
})

app.get("/investment-tasks", verifyAccessToken, async (req, res) => {
  const userId = req.user?.id

  try {
    const completedTasksRes = await pool.query(
      "SELECT task_id FROM completed_investment WHERE user_id = $1",
      [userId]
    );

    const completedTaskIds = completedTasksRes.rows.map(row => row.task_id);

    // Fetch completed tasks
    let completedTasks = [];
    let incompleteTasks = [];
    if (completedTaskIds.length > 0) {
      const placeholders = completedTaskIds.map((_, i) => `$${i + 1}`).join(", ");

      const completedTasksResult = await pool.query(
        `SELECT * FROM investment_tasks WHERE id IN (${placeholders})`,
        completedTaskIds
      );

      const incompleteTasksResult = await pool.query(
        `SELECT * FROM investment_tasks WHERE id NOT IN (${placeholders})`,
        completedTaskIds
      );

      completedTasks = completedTasksResult;
      incompleteTasks = incompleteTasksResult;
    } else {
      // All tasks are incomplete if none are completed
      incompleteTasks = await pool.query("SELECT * FROM investment_tasks");
    }


    res.json({
      success: true,
      completedTasks: completedTasks.rows,
      incompleteTasks: incompleteTasks.rows,
    });
  } catch (err) {
    console.error("Error verifying token:", err);
    res.json({ message: "Invalid token", success: false });
  }
})


app.get("/referral-tasks", verifyAccessToken , async (req, res) => {
  const userId = req.user?.id

  try {

    // Get user referral count
    const userRes = await pool.query("SELECT referral_number, referral_code FROM users WHERE id = $1", [userId]);
    const referredCount = userRes.rows[0]?.referral_number;

    // Get IDs of already completed tasks
    const userCompletedTasks = await pool.query(
      "SELECT task_id FROM completed_referral WHERE user_id = $1",
      [userId]
    );
    const completedTaskIds = userCompletedTasks.rows.map(row => row.task_id);

    // Get all eligible tasks based on current referred count
    const eligibleTasksRes = await pool.query("SELECT * FROM referral_tasks WHERE amount <= $1", [referredCount]);
    const eligibleTasks = eligibleTasksRes.rows;

    // Filter only newly completed tasks
    const newTasks = eligibleTasks.filter(task => !completedTaskIds.includes(task.id));

    // Reward and insert only new tasks
    for (const task of newTasks) {
      await pool.query(
        "INSERT INTO completed_referral(user_id, task_id) VALUES ($1, $2)",
        [userId, task.id]
      );
      await pool.query("UPDATE users SET point = point + $1 WHERE id = $2", [task.reward_point, userId]);
    }

    // For response, recompute completed and incomplete tasks
    const allTasks = await pool.query("SELECT * FROM referral_tasks");
    const completedTasks = allTasks.rows.filter(task => completedTaskIds.includes(task.id) || newTasks.find(t => t.id === task.id));
    const incompleteTasks = allTasks.rows.filter(task => !completedTasks.find(t => t.id === task.id));

    res.json({
      success: true,
      completedTasks,
      incompleteTasks,
      referralCode: userRes.rows[0]?.referral_code,
    });

  } catch (err) {
    console.error("Error fetching referral tasks:", err);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});




const connection = new Connection(process.env.RPC_URL, "confirmed");
const WALLET_ADDRESS = "A7PB8vLhPAh93QCpgZFTuHWY6tq7rQGHfByxy3CjyRWr";

app.post("/verify-transaction", verifyAccessToken, async (req, res) => {
  const { signature, amount, fromPubkey, taskId, reward } = req.body;
  const userId = req.user?.id

  try {
    const tx = await connection.getParsedTransaction(signature, {
      maxSupportedTransactionVersion: 0,
    });

    if (!tx) return res.status(400).json({ success: false, message: "Transaction not found" });

    // Confirm the transaction was successful
    if (tx.meta.err) {
      return res.status(400).json({ success: false, message: "Transaction failed" });
    }

    // Loop through all instructions and find a transfer to wallet
    const transferInstruction = tx.transaction.message.instructions.find((ix) => {
      return (
        ix.parsed?.type === "transfer" &&
        ix.parsed.info.destination === WALLET_ADDRESS &&
        ix.parsed.info.source === fromPubkey
      );
    });

    if (!transferInstruction) {
      return res.status(400).json({ success: false, message: "No valid transfer found" });
    }

    // Check amount
    const lamportsSent = transferInstruction.parsed.info.lamports;
    const solSent = lamportsSent / 1e9;

    if (solSent < amount) {
      return res.status(400).json({ success: false, message: "Insufficient amount sent" });
    }

    await pool.query("INSERT INTO completed_investment (user_id, task_id, address, reward_point) VALUES ($1, $2, $3, $4)", [userId, taskId, fromPubkey, reward]);
    await pool.query("UPDATE users SET point = point + $1 WHERE id = $2", [reward, userId]);
    // ✅ Valid transaction
    return res.status(200).json({ success: true, message: "Transaction verified" });

  } catch (err) {
    console.error("Verification error:", err);
    return res.status(500).json({ success: false, message: "Server error verifying transaction" });
  }
});


app.post("/complete-task", verifyAccessToken, async (req, res) => {
  const userId = req.user?.id
  const { taskId, reward_point } = req.body;

  try {
    await pool.query("INSERT INTO completed_tasks (user_id, task_id) VALUES ($1, $2)", [userId, taskId]);
    await pool.query("UPDATE users set point = point + $1 WHERE id = $2", [reward_point, userId]);
    res.json({ success: true });
  } catch (err) {
    console.error("Error verifying token:", err);
    res.json({ message: "Invalid token or database", success: false });
  }
})

app.get("/get-telegramId", verifyAccessToken, async (req, res) => {
  const userId = req.user?.id

  try {
    const telegramId = await pool.query("SELECT telegram_id FROM users WHERE id = $1", [userId]);
    if (!telegramId.rows[0]?.telegram_id) {
      return res.json({ message: "Not connected to telegram ", success: false });
    }
    res.json({ telegramId: telegramId.rows[0].telegram_id, success: true });
  } catch (err) {
    console.error("Error verifying token:", err);
    res.json({ message: "Invalid token or database", success: false });
  }
})

app.post("/claim-daily-reward", verifyAccessToken, async (req, res) => {
  const userId = req.user?.id

  try {

    const dailyReward = await pool.query("UPDATE daily_reward SET claimed = $1 WHERE user_id = $2 RETURNING *", [true, userId]);
    const updatedPoint = dailyReward.rows[0].streak * 1000;
    await pool.query("UPDATE users SET point = point + $1 WHERE id = $2", [updatedPoint, userId]);

    res.json({ message: "Daily reward claimed successfully", success: true });
  } catch (err) {
    console.error("Error verifying token:", err);
    res.json({ message: "Invalid token or database", success: false });
  }
})

app.get("/leaderboard", verifyAccessToken, async (req, res) => {
  const userId = req.user?.id

  try {
    const leaderboard = await pool.query(`SELECT id,
            name,
            point,
            avatar_url,
            RANK() OVER (ORDER BY point DESC) AS rank
            FROM users
            ORDER BY point DESC
            LIMIT 10; `);
    const currentUserRank = await pool.query(`SELECT * FROM ( SELECT 
            id,
            name,
            point,
            avatar_url,
            RANK() OVER (ORDER BY point DESC) AS rank
            FROM users
            ) ranked
            WHERE id = $1;
`, [userId]);

    if (currentUserRank.rowCount === 0) {
      res.clearCookie("refreshToken", { httpOnly: true, secure: true, sameSite: "None" });
      return res.json({ message: "User not found", success: false });
    }

    const topThree = leaderboard.rows.slice(0, 3)
    const others = leaderboard.rows.slice(3, 10)
    const currentUser = currentUserRank.rows[0]

    res.json({
      message: "Leaderboard fetched successfully",
      success: true,
      topThree: topThree,
      others: others,
      currentUser: currentUser
    });
  } catch (err) {
    console.error("Error verifying token:", err);
    res.json({ message: "failed to fetch leaderboard", success: false });
  }
})


app.get("/get-referral-bonus", verifyAccessToken, async (req, res) => {
  const userId = req.user?.id

  try {

    const user = await pool.query("SELECT referral_code FROM users WHERE id = $1", [userId]);
    const referedFriends = await pool.query("SELECT point FROM users WHERE invited_by = $1", [user.rows[0].referral_code]);
    const bonusTable = await pool.query("SELECT previous_total FROM referral_bonus WHERE user_id = $1", [userId]);

    let total = 0;
    for (let friend of referedFriends.rows) {
      total += friend.point;
    }

    const previous_total = bonusTable.rows[0]?.previous_total || 0;
    const currentTotal = total - previous_total;

    const bonusToAdd = Math.floor(currentTotal * 0.1);
    const updatedRefBonus = await pool.query(
      "UPDATE referral_bonus SET previous_total = previous_total + $1, total_bonus = total_bonus + $2 WHERE user_id = $3 RETURNING *",
      [currentTotal, bonusToAdd, userId]
    );
    await pool.query("UPDATE users SET point = point + $1 WHERE id = $2", [bonusToAdd, userId]);

    res.json({ updated: updatedRefBonus.rows[0], success: true });
  } catch (err) {
    console.error("Error verifying token:", err);
    res.json({ message: "Invalid token or database", success: false });
  }
});

app.post("/send-reset-otp", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await pool.query("SELECT 1 FROM users WHERE email = $1", [email]);
    if (user.rowCount === 0) {
      return res.json({ success: false, message: "User not found with this email" });
    }

    const code = String(Math.floor(Math.random() * 999999) + 1).padStart(6, '0');
    const verificationCode = await getVerificationCode(email, code); // Send email code
    if (!verificationCode.success) {
      return res.json({ success: false, message: "Failed to send verification code" });
    }

    const tempPassword = String(Math.floor(Math.random() * 999999) + 1).padStart(10, '0');
    await pool.query(`
      INSERT INTO pending_verifications (email, hashed_password, code)
      VALUES ($1, $2, $3)
      ON CONFLICT (email) DO UPDATE SET hashed_password = $2, code = $3, created_at = NOW()
    `, [email, tempPassword, code]);

    res.json({ success: true, message: "Verification code sent to your email." });
  } catch (error) {
    console.log("Error occurred on sending reset OTP:", error);
    res.json({ success: false, message: "Failed to send reset OTP" });
  }
});

app.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {

    const result = await pool.query(`
      SELECT * FROM pending_verifications
      WHERE email = $1 AND code = $2 AND created_at > NOW() - INTERVAL '10 minutes'
    `, [email, otp]);

    if (result.rowCount === 0) {
      return res.json({ success: false, message: "Invalid or expired verification code" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    await pool.query(`
      UPDATE users SET password = $1 WHERE email = $2
    `, [hashedPassword, email]);

    await pool.query("DELETE FROM pending_verifications WHERE email = $1", [email]);

    res.json({ success: true, message: "Password reset successfully! now you can login" });
  } catch (error) {
    console.error("❌ Error resetting password:", error);
    res.json({ success: false, message: "Failed to reset password" });
  }
});





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