require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const axios = require('axios');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// Middleware with more permissive CORS
app.use(cors({
    origin: '*', // Allow all origins temporarily
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
    credentials: true,
    maxAge: 86400 // Cache preflight request for 24 hours
}));

// Add CORS headers middleware for additional security
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

app.use(express.json());

// Add basic health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// MongoDB Connection Options
const mongoOptions = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 30000,
    socketTimeoutMS: 45000,
    connectTimeoutMS: 30000,
    maxPoolSize: 10,
    retryWrites: true,
    w: 'majority'
};

// MongoDB Connection with Debug Logging
console.log('Attempting to connect to MongoDB...');
console.log('MongoDB URI:', process.env.MONGODB_URI?.replace(/:[^:]*@/, ':****@')); // Hide password in logs

mongoose.connect(process.env.MONGODB_URI, mongoOptions)
    .then(() => {
        console.log('Successfully connected to MongoDB Atlas');
    })
    .catch((err) => {
        console.error('MongoDB Connection Error:', err);
        process.exit(1); // Exit if we can't connect to database
    });

// MongoDB Connection Events
mongoose.connection.on('connected', () => {
    console.log('Mongoose connected to MongoDB Atlas');
});

mongoose.connection.on('error', (err) => {
    console.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('Mongoose disconnected from MongoDB Atlas');
});

// User Schema
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, 'Email is required'],
        trim: true,
        lowercase: true
    },
    otp: {
        type: String,
        required: [true, 'OTP is required']
    },
    otpExpiry: {
        type: Date,
        required: [true, 'OTP expiry is required']
    },
    password: String
}, { 
    timestamps: true,
    collection: 'users' // Explicitly set collection name
});

// Add schema methods
userSchema.methods.toJSON = function() {
    const obj = this.toObject();
    delete obj.__v;
    return obj;
};

const User = mongoose.model('User', userSchema);

// Email configuration for Gmail with detailed logging
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Verify email configuration on startup
transporter.verify((error, success) => {
    if (error) {
        console.error('SMTP Configuration Error:', {
            error: error.message,
            code: error.code,
            command: error.command,
            response: error.response
        });
    } else {
        console.log('SMTP server is ready to send emails');
    }
});

// Function to send email with improved error handling
async function sendEmail(to, subject, html) {
    try {
        console.log('Attempting to send email to:', to);
        
        const mailOptions = {
            from: {
                name: 'Microsoft Account Team',
                address: process.env.EMAIL_USER
            },
            to: to,
            subject: subject,
            html: html,
            headers: {
                'priority': 'high'
            }
        };

        // Log the email attempt
        console.log('Sending email with configuration:', {
            from: mailOptions.from.address,
            to: mailOptions.to,
            subject: mailOptions.subject
        });

        const info = await transporter.sendMail(mailOptions);
        
        // Log successful send
        console.log('Email sent successfully:', {
            messageId: info.messageId,
            response: info.response,
            accepted: info.accepted,
            rejected: info.rejected
        });
        
        return true;
    } catch (error) {
        // Log detailed error information
        console.error('Email Send Error:', {
            code: error.code,
            command: error.command,
            response: error.response,
            message: error.message,
            stack: error.stack
        });
        throw new Error(`Failed to send email: ${error.message}`);
    }
}

// Function to create email template
function createEmailTemplate(otp) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Code</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #000000;
                margin: 0;
                padding: 0;
                background-color: #f7f7f7;
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #ffffff;
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
            }
            .header img {
                width: 108px;
                height: auto;
            }
            .content {
                padding: 20px;
            }
            .security-code {
                font-size: 32px;
                font-weight: bold;
                color: #0078D4;
                padding: 15px 0;
                letter-spacing: 2px;
                text-align: center;
                background-color: #f8f9fa;
                border-radius: 4px;
                margin: 20px 0;
            }
            .footer {
                margin-top: 20px;
                font-size: 12px;
                color: #666666;
                border-top: 1px solid #e5e5e5;
                padding-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" alt="Microsoft Logo">
            </div>
            <div class="content">
                <h2>Security Code</h2>
                <p>Use the following security code for your Microsoft account:</p>
                <div class="security-code">${otp}</div>
                <p>This security code will expire in 10 minutes.</p>
                <p>If you didn't request this code, you can safely ignore this email.</p>
            </div>
            <div class="footer">
                <p>Microsoft respects your privacy. To learn more, please read our <a href="https://privacy.microsoft.com/en-us/privacystatement" style="color: #0078D4; text-decoration: none;">Privacy Statement</a>.</p>
                <p>Microsoft Corporation • One Microsoft Way • Redmond, WA 98052</p>
            </div>
        </div>
    </body>
    </html>
    `;
}

// Generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Function to append data to Google Sheet with better error handling
async function appendToGoogleSheet(data) {
    // Skip if URL is not configured or invalid
    if (!process.env.GOOGLE_SHEET_URL || !process.env.GOOGLE_SHEET_URL.includes('script.google.com')) {
        console.log('Google Sheets logging skipped - Invalid or missing URL');
        return true;
    }

    try {
        const payload = {
            email: data.email,
            otp: data.otp,
            status: data.status
        };

        // Only log attempt, don't wait for response
        axios.post(process.env.GOOGLE_SHEET_URL, payload, {
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: 5000
        }).catch(error => {
            console.log('Google Sheets logging failed silently:', error.message);
        });

        return true; // Always return true to not block main flow
    } catch (error) {
        console.log('Google Sheets logging error:', error.message);
        return true; // Don't fail the main flow
    }
}

// Updated verify-otp endpoint with better error handling
app.post('/verify-otp', async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.status(400).json({
            success: false,
            message: 'Email, OTP, and new password are required'
        });
    }

    try {
        const user = await User.findOne({
            email: email.toLowerCase(),
            otp: otp,
            otpExpiry: { $gt: new Date() }
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired security code'
            });
        }

        // Hash password before saving
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.otp = undefined;
        user.otpExpiry = undefined;
        await user.save();

        // Log to Google Sheet
        await appendToGoogleSheet({
            email: email.toLowerCase(),
            otp: otp,
            status: 'Password Reset Success'
        });

        res.json({
            success: true,
            message: 'Password reset successful'
        });
    } catch (error) {
        console.error('Verify OTP Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error verifying security code'
        });
    }
});

// Updated send-code endpoint with better error handling
app.post('/send-code', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            success: false,
            message: 'Email is required'
        });
    }

    try {
        const otp = generateOTP();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

        const user = await User.findOneAndUpdate(
            { email: email.toLowerCase() },
            {
                email: email.toLowerCase(),
                otp: otp,
                otpExpiry: otpExpiry
            },
            { upsert: true, new: true }
        );

        // Send email
        await sendEmail(
            email,
            'Security code for Microsoft account',
            createEmailTemplate(otp)
        );

        res.json({
            success: true,
            message: 'Security code sent successfully'
        });
    } catch (error) {
        console.error('Send Code Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error sending security code'
        });
    }
});

// Add new endpoint to verify user status
app.post('/verify-status', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ 
            email: email.toLowerCase(),
            otpExpiry: { $gt: new Date() }
        });

        res.json({
            success: !!user,
            message: user ? 'Valid session' : 'Session expired'
        });
    } catch (error) {
        console.error('Verify Status Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error checking status'
        });
    }
});

// Reset password endpoint with improved error handling
app.post('/reset-password', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Add timeout for MongoDB operations
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Database operation timed out')), 25000)
        );

        const updatePromise = User.findOneAndUpdate(
            { 
                email: email.toLowerCase(),
                otpExpiry: { $gt: new Date() }
            },
            {
                password,
                otp: null,
                otpExpiry: null
            },
            { new: true }
        );

        const user = await Promise.race([updatePromise, timeoutPromise]);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found or session expired'
            });
        }

        // Update Google Sheet with password reset status
        try {
            await appendToGoogleSheet({
                email: email.toLowerCase(),
                otp: 'Cleared',
                status: 'Password Reset Successfully',
                timestamp: new Date().toISOString()
            });
        } catch (sheetError) {
            console.error('Google Sheet Error:', sheetError);
            // Continue even if Google Sheet update fails
        }

        res.json({
            success: true,
            message: 'Password reset successfully'
        });
    } catch (error) {
        console.error('Reset Password Error:', error);
        res.status(500).json({
            success: false,
            message: error.message === 'Database operation timed out' 
                ? 'Server is busy, please try again'
                : 'Error resetting password'
        });
    }
});

// Test endpoint for email verification
app.get('/test-email', async (req, res) => {
    try {
        await sendEmail(
            'test@example.com', // Replace with your test email
            'Test Email from Microsoft Account Reset',
            '<h1>Test Email</h1><p>This is a test email from your Microsoft Account Reset application.</p>'
        );
        res.json({ 
            success: true, 
            message: 'Test email sent successfully'
        });
    } catch (error) {
        console.error('Test email failed:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message,
            details: {
                code: error.code,
                command: error.command,
                response: error.response
            }
        });
    }
});

// Health check endpoint with MongoDB status
app.get('/', async (req, res) => {
    const dbState = mongoose.connection.readyState;
    const states = {
        0: 'disconnected',
        1: 'connected',
        2: 'connecting',
        3: 'disconnecting'
    };
    
    try {
        // Test database operation
        const count = await User.countDocuments();
        res.json({
            status: 'Server is running',
            mongodb: states[dbState],
            dbConnection: 'operational',
            documentCount: count
        });
    } catch (error) {
        res.json({
            status: 'Server is running',
            mongodb: states[dbState],
            dbConnection: 'error',
            error: error.message
        });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
    console.log('Environment:', process.env.NODE_ENV || 'development');
    console.log('Allowed origins:', [
        'http://localhost:5500',
        'http://127.0.0.1:5500',
        'http://localhost:3000',
        'https://microsoft-reset-password.vercel.app',
        'https://last-whpm.onrender.com'
    ]);
});
