import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const cors = require('cors');

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Explicit preflight handling
app.options('*', cors());

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
    const {
      fullName,
      full_name,
      staffId,
      staff_id,
      email,
      password,
      department,
      role = 'admin'
    } = req.body;

    const resolvedName = fullName || full_name;
    const resolvedStaffId = staffId || staff_id;
    const resolvedDept = department || (role === 'admin' ? 'Property Custodian' : 'Student');

    if (!email || !password || !resolvedName) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    const cleanEmail = email.trim().toLowerCase();

    if (role === 'admin') {
      // Check if already registered
      const { data: existing } = await supabase
        .from('profiles')
        .select('id')
        .eq('email', cleanEmail)
        .maybeSingle();

      if (existing) {
        return res.status(400).json({ error: 'An admin with this email already exists.' });
      }

      // Insert directly into profiles table
      const { data, error } = await supabase
        .from('profiles')
        .insert([{
          full_name: resolvedName,
          staff_id: resolvedStaffId,
          email: cleanEmail,
          password_hash: password, // plain text for testing
          department: resolvedDept,
          role: 'admin',
          is_verified: true
        }])
        .select()
        .single();

      if (error) {
        console.error('Supabase profile insert error:', error);
        return res.status(500).json({ error: error.message });
      }

      return res.status(201).json({
        message: 'Admin registered and activated successfully!',
        profile: data
      });
    } else {
      // Borrower flow
      const { data: existing } = await supabase
        .from('borrowers')
        .select('id')
        .eq('email', cleanEmail)
        .maybeSingle();

      if (existing) {
        return res.status(400).json({ error: 'A borrower with this email already exists.' });
      }

      const { data, error } = await supabase
        .from('borrowers')
        .insert([{
          full_name: resolvedName,
          staff_id: resolvedStaffId,
          email: cleanEmail,
          password: password,
          department: resolvedDept,
          role: 'borrower',
          is_verified: true
        }])
        .select()
        .single();

      if (error) {
        console.error('Supabase borrower insert error:', error);
        return res.status(500).json({ error: error.message });
      }

      return res.status(201).json({
        message: 'Borrower registered successfully!',
        user: data
      });
    }
  } catch (err) {
    console.error('Critical Register Handler Error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
});
// 3. Fetch all requisitions for Admin Desk
app.get('/api/requisitions', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('requisitions')
      .select('*')
      .order('requested_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Update Requisition Status (Approve / Reject)
app.patch('/api/requisitions/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const { data, error } = await supabase
      .from('requisitions')
      .update({ status })
      .eq('id', id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SmartTrack Server active on port ${PORT}`));
