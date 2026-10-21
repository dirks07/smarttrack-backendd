import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_ROLE_KEY || ''
);

// Helper function to send emails via Brevo HTTPS REST API
async function sendVerificationEmail(recipientEmail, recipientName, activationUrl) {
  const apiKey = process.env.BREVO_API_KEY;
  if (!apiKey) throw new Error('BREVO_API_KEY is missing');

  const senderEmail = process.env.SENDER_EMAIL || 'dirkshaned@gmail.com';

  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': apiKey,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      sender: { name: 'CDM SmartTrack', email: senderEmail },
      to: [{ email: recipientEmail, name: recipientName }],
      subject: 'Activate Your CDM SmartTrack Account',
      htmlContent: `
        <div style="background:#060a0f;color:#fff;padding:24px;text-align:center;font-family:sans-serif;border-radius:12px;">
          <h2 style="color:#10b981;letter-spacing:1px;">CDM SMARTTRACK</h2>
          <p style="color:#cbd5e1;">Hello ${recipientName}, click below to activate your account:</p>
          <a href="${activationUrl}" style="background:#10b981;color:#022c22;padding:12px 24px;text-decoration:none;font-weight:bold;display:inline-block;border-radius:6px;margin:20px 0;">Activate My Account</a>
          <p style="color:#64748b;font-size:12px;">This link will expire in 15 minutes.</p>
        </div>
      `
    })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.message || 'Brevo API error sending email');
  }
  return data;
}

app.get('/', (req, res) => {
  res.send('SmartTrack API is live and operational.');
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

    const baseUrl = process.env.APP_URL || 'https://smarttrack-backendd.onrender.com';
    const activationUrl = `${baseUrl}/api/auth/verify?token=${verificationToken}`;

    await sendVerificationEmail(cleanEmail, fullName.trim(), activationUrl);

    console.log(`[Email Dispatched via Brevo] Activation sent to: ${cleanEmail}`);
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
    res.send('<h2 style="font-family:sans-serif;text-align:center;margin-top:40px;color:#10b981;">Account successfully activated! You can now return to the workstation and sign in.</h2>');
  } catch {
    res.status(400).send('Invalid or expired verification link.');
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'ID/Email and password required.' });
    }

    const cleanIdentifier = email.trim();

    // Query profiles matching EITHER the email OR the staff_id
    const { data: user, error } = await supabase
      .from('profiles')
      .select('*')
      .or(`email.ilike.${cleanIdentifier},staff_id.eq.${cleanIdentifier}`)
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({ error: 'User does not exist.' });
    }

    if (!user.is_verified) {
      return res.status(403).json({ error: 'Account not activated. Please verify via email.' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid password.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, staffId: user.staff_id, role: user.role },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    res.json({
      token,
      profile: {
        fullName: user.full_name,
        staffId: user.staff_id,
        department: user.department,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SmartTrack Server active on port ${PORT}`));
