import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import crypto from "crypto";
import nodemailer from "nodemailer"
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth20"
import "dotenv/config";
import cors from 'cors';
import bcrypt from "bcrypt";
import pkg from "pg";
const { Pool } = pkg;
import connectPgSimple from "connect-pg-simple";
import { disconnect } from "process";


const PGStore = connectPgSimple(session);
const app = express();
const port = 3000;
const saltRounds = 10;
const telegramBotToken = process.env.TELEGRAM_BOT_TOKEN;

// database configuration
const pool = new Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT
});
pool.connect();

// Middleware order is crucial!  Initialize session storage before Passport.
app.use(
  session({
    store: new PGStore({
      pool: pool,
      tableName: 'session'
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true
    }    
  })
);

app.use(cors({
  origin: ['http://localhost:5173', 'https://bricks-1i79.onrender.com'],
  credentials: true
}));


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Passport serializeUser and deserializeUser (define before routes)
 passport.serializeUser((user, cb) => {
  console.log("Serializing user:", user); // Debugging line
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];
    if (!user) {
      console.log("User not found during deserialization"); // Debugging line
      return cb(new Error('User not found'));
    }

    user.registered = true;
    console.log("Deserializing user:", user); // Debugging line
    cb(null, user);
  } catch (err) {
    console.error("Error deserializing user:", err);
    cb(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});


function verifyTelegrmAuth(data){
  const authData = URLSearchParams(data);
  const hash = authData.get("hash");
  authData.delete("hash");

  const sortedData = [...authData].sort().map(([Key, val]) => `${Key}=${val}`).join("\n");
  const secretKey = crypto.createHmac("sha256").update(telegramBotToken).digest();
  const expectedHash = crypto.createHmac("sha256", secretKey).update(sortedData).digest("hex");

  return hash === expectedHash;
}


              //home route

app.get("/isAuthenticated", (req, res)=>{
  if(req.isAuthenticated()){
    res.json({authenticated: true})
  }else{
    res.json({authenticated: false})
  }
})


app.get("/home", async (req, res) => {
  
  if (req.isAuthenticated()) {
    res.json(req.user);
    console.log(req.user);
  } else {
    res.json({ email: "example@gmail.com", registered: false});
    console.log("no user");
  }
});

app.get("/dashboard", async (req, res) => {
  
  if (req.isAuthenticated()) {
    res.json(req.user);
    console.log(req.user);
  } else {
    res.json({ email: "---", registered: false});
    console.log("no user");
  }
});



              //register route
 app.post("/register", async (req, res, next) => {
   const { email, password } = req.body;

  try {
 
    console.log("registration started")
   
    console.log("Request body:", req.body); // Debugging line

    const checkUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkUser.rows.length > 0) {
      return res.json({ success: false, message: "User already registered, please login" });
    }

    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.log("Error on hashing password ", err);
        return res.status(500).json({ success: false, message: "Error occured during registration please try again." });
      }

      try {
        const insertUser = await pool.query(
          "INSERT INTO users (email, password, is_verified, authenticator) VALUES ($1, $2, $3, $4) RETURNING *",
          [email, hash, false, "email"]
        );
        const insertAddress = await pool.query("INSERT INTO wallet (address, user_id) VALUES ($1, $2) RETURNING *", [null, insertUser.rows[0].id])
        const user = insertUser.rows[0];
        console.log("User inserted into DB:", user, insertAddress.rows[0]); // Debugging line

        const verificationToken = crypto.randomBytes(32).toString('hex');
        await pool.query(
          "INSERT INTO verification_token (user_id, token) VALUES ($1, $2)",
          [user.id, verificationToken]
        );
        const verificationLink = `http://localhost:3000/verify-email?token=${verificationToken}`;
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Verify your email',
          html: `<p>Click the link below to verify your email:</p><a href="${verificationLink}">${verificationLink}</a>`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.log(error);
            return res.json({ success: false, message: "Failed to send verification email" });
          }
          res.json({ success: true, message: "Verification email sent. Please check your inbox." });
        });
  

    
      } catch (dbError) {
        console.error("Database error:", dbError);
        return res.json({success: false, message: "Error occured during registration please try again.",  });
      }
    });
  } catch (error) {
    console.error("Error occurred on registering user ", error);
    res.json({success: false, message: "Registration failed" });
    //status(500).
  }
}); 

              //logout route
app.post("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      res.json({failed: true})
      return next(err);
    }
    res.json({failed: false})
  })
});


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

    req.login({ id: user.id }, (err) => {  // Use only the id for serialization
      if (err) {
        return next(err);
      }
      console.log("User authenticated successfully");
      user.success = true;
      return res.json(user); // Send user data to the frontend
    });

  } catch (err) {
    console.error("Error during authentication:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});



              //connect wallet route
app.post("/connect-wallet", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" }); // Check if user is authenticated
  }
  const { address } = req.body;
  try {
    const insertAddress = await pool.query("UPDATE wallet SET address = $1 WHERE user_id = $2 RETURNING *", [address, req.user.id]);
    console.log(insertAddress.rows[0]);
    res.json(insertAddress.rows[0]);
  } catch (error) {
    console.error("error on connecting wallet ", error);
    res.status(500).json({ message: "Failed to connect wallet" });
  }

});


              //get wallet route
app.get("/get-wallet", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" }); // Check if user is authenticated
  }
  try {
    // WHERE user_id = $1", [req.user.id])
    const getWallet = await pool.query("SELECT * FROM wallet");
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
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" }); // Check if user is authenticated
  }
  try {
    await pool.query("UPDATE wallet SET address = $1 WHERE user_id = $2 RETURNING *", [null, req.user.id]);
    res.json({ success: true });
  } catch (error) {
    console.error("error on disconnecting wallet ", error);
    res.status(500).json({ message: "Failed to disconnect wallet" });
  }
 });


             //local strategy for signin
 passport.use(
   "local",
   new Strategy(async function verify(email, password, cb) {
     try {
       const selectUser = await db.query("SELECT * FROM users WHERE email = $1 ", [email]);
       if (selectUser.rows.length > 0) {
         const user = selectUser.rows[0];
         const storedHashedPassword = user.password;
         bcrypt.compare(password, storedHashedPassword, (err, valid) => {
           if (err) {
             console.error("Error comparing passwords:", err);
             return cb(err);
           } else {
             if (valid) {
              console.log(user);
               return cb(null, user);
             } else {
              console.log("user not logged in");
               return cb(null, false);
             }
           }
         });
       } else {
        console.log("user not found with this email")
         return cb("User not found");
       }
     } catch (err) {
       console.log(err);
     }
   })
 );

 passport.use(
   "google",
   new GoogleStrategy(
     {
       clientID: process.env.GOOGLE_CLIENT_ID,
       clientSecret: process.env.GOOGLE_CLIENT_SECRET,
       callbackURL: "https://bricks-1i79.onrender.com/auth/google/dashboard",
       userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
     },
     async (accessToken, refreshToken, profile, cb) => {
       try {
         const result = await pool.query("SELECT * FROM users WHERE email = $1", [
          profile.emails[0].value

         ]);
         if (result.rows.length === 0) {
           const newUser = await pool.query(
             "INSERT INTO users (email, password, authenticator, is_verified) VALUES ($1, $2, $3, $4) RETURNING *",
             [profile.emails[0].value, null, "google", true]
           );
           return cb(null, newUser.rows[0]);
         } else {
           return cb(null, result.rows[0]);
         }
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

 app.get(
   "/auth/google/dashboard",
   passport.authenticate("google", {
     successRedirect: "http://localhost:5173/dashboard",
     failureRedirect: "http://localhost:5173/signin"
   })
 );

 app.get("/verify-email", async (req, res) => {
  const { token } = req.query;

  try {
    const result = await pool.query(
      "SELECT * FROM verification_token WHERE token = $1",
      [token]
    );

    if (result.rows.length === 0) {
      return res.json({ success: false, message: "Invalid or expired verification token" });
      console.log("token expired");
    }

    const userId = result.rows[0].user_id;

    const user = await pool.query("UPDATE users SET is_verified = true WHERE id = $1 RETURNING *", [userId]);
    await pool.query("DELETE FROM verification_token WHERE token = $1", [token]);

    res.json({ success: true, message: "Email verified successfully" });

    req.login({ user}, (err) => {  
      if (err) {
        return next(err);
      }
      res.redirect("/dashboard")
    });

  } catch (error) {
    console.error("Error verifying email:", error);
    res.json({ success: false, message: "Failed to verify email" });
  }
});


 
 app.post("/auth/telegram", async (req, res, next) => {
   console.log("Telegram Authentication Request Received");
   const data = req.body;
   console.log("Received Data:", data || null);
 
   if (!verifyTelegrmAuth(data)) {
     return res.json({ success: false, message: "Invalid telegram data" });
   }
 
   const telegramId = data.id;

   try {
     const user = await pool.query("SELECT * FROM users WHERE telegram_id = $1", [telegramId]);
 
     if (user.rows.length === 0) {
       const newUser = await pool.query(
         "INSERT INTO users (email, is_verified, authenticator, telegram_id) VALUES ($1, $2, $3, $4) RETURNING *", 
         [null, true, "telegram", telegramId]
       );
 
       req.login(newUser.rows[0], (err) => {  
         if (err) {
           return next(err);
         }
         res.json({ success: true });
       });
     } else {
       req.login(user.rows[0], (err) => {  
         if (err) {
           return next(err);
         }
         res.json({ success: true });
       });
     }
   } catch (error) {
     console.log("Error on login with Telegram:", error);
     res.json({ success: false, message: "Authorization failed, please try again" });
   }
 });
 


// Error-handling middleware (must be defined after routes)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server is running on port ${port}`);
});