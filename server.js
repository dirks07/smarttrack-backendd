import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_ROLE_KEY || ''
);

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT) || 465,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, staffId, department, email, password } = req.body;
    if (!email || !password || !fullName) {
      return res.status(400).json({ error: 'All fields required' });
    }
    const cleanEmail = email.trim().toLowerCase();
    const passwordHash = await bcrypt.hash(password, 10);
    const verificationToken = jwt.sign({ email: cleanEmail }, process.env.JWT_SECRET || 'secret', { expiresIn: '15m' });

    await supabase.from('profiles').upsert({
      full_name: fullName.trim(),
      staff_id: staffId || null,
      department: department || 'Property Custodian',
      email: cleanEmail,
      password_hash: passwordHash,
      role: 'admin',
      is_verified: false,
      verification_token: verificationToken,
    }, { onConflict: 'email' });

    const activationUrl = `${process.env.APP_URL || 'http://localhost:5000'}/api/auth/verify?token=${verificationToken}`;

    await transporter.sendMail({
      from: `"CDM SmartTrack" <${process.env.SMTP_USER}>`,
      to: cleanEmail,
      subject: 'Activate Your CDM SmartTrack Account',
      html: `
        <div style="background:#060a0f;color:#fff;padding:24px;text-align:center;font-family:sans-serif;">
          <h2>CDM SMARTTRACK</h2>
          <p>Hello ${fullName}, click below to activate your account:</p>
          <a href="${activationUrl}" style="background:#10b981;color:#000;padding:12px 24px;text-decoration:none;font-weight:bold;display:inline-block;border-radius:6px;margin:16px 0;">Activate My Account</a>
        </div>
      `
    });

    console.log(`[Email Sent] Activation sent to: ${cleanEmail}`);
    res.status(201).json({ success: true, message: `Email dispatched to ${cleanEmail}` });
  } catch (err) {
    console.error('Registration failed:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/verify', async (req, res) => {
  try {
    const decoded = jwt.verify(req.query.token, process.env.JWT_SECRET || 'secret');
    await supabase.from('profiles').update({ is_verified: true, verification_token: null }).eq('email', decoded.email);
    res.send('<h2 style="font-family:sans-serif;text-align:center;margin-top:40px;">Account successfully activated! You can now sign in.</h2>');
  } catch {
    res.status(400).send('Invalid or expired verification link.');
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user, error } = await supabase.from('profiles').select('*').eq('email', email.trim().toLowerCase()).single();
    if (error || !user) return res.status(401).json({ error: 'User does not exist.' });
    if (!user.is_verified) return res.status(403).json({ error: 'Account not activated. Please verify via email.' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid password.' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
    res.json({ token, profile: { fullName: user.full_name, staffId: user.staff_id, department: user.department } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SmartTrack Server active at http://localhost:${PORT}`));
