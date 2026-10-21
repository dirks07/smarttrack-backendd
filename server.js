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
    const { staff_id, full_name, email, password, department } = req.body;

    const { data, error } = await supabase
      .from('borrowers')
      .insert([
        {
          staff_id: staff_id.trim(),
          full_name: full_name.trim(),
          email: email.trim().toLowerCase(),
          password: password, // stores plain text
          department: department || 'General',
          is_verified: true
        }
      ])
      .select()
      .single();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(201).json({ message: 'Borrower registered successfully', user: data });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
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
    // Support all possible payload property names from the mobile app
    const identifier = req.body.identifier || req.body.email || req.body.staff_id;
    const password = req.body.password;

    if (!identifier || !password) {
      return res.status(400).json({ error: 'ID/Email and password are required' });
    }

    const cleanIdentifier = String(identifier).trim();

    // Query borrowers table by staff_id or email
    const { data: borrower, error } = await supabase
      .from('borrowers')
      .select('*')
      .or(`staff_id.eq.${cleanIdentifier},email.ilike.${cleanIdentifier}`)
      .single();

    if (error || !borrower) {
      return res.status(404).json({ error: 'Borrower account not found' });
    }

    // Direct plain-text password match
    if (borrower.password !== password) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    if (borrower.is_verified === false) {
      return res.status(403).json({ error: 'Account not yet verified' });
    }

    return res.status(200).json({
      message: 'Login successful',
      user: {
        id: borrower.id,
        staff_id: borrower.staff_id,
        full_name: borrower.full_name,
        email: borrower.email,
        department: borrower.department,
        role: 'borrower'
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SmartTrack Server active on port ${PORT}`));
