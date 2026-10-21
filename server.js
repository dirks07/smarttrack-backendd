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

// 1. Fetch live catalog for both Mobile and Admin
// 1. Fetch live catalog
app.get('/api/catalog', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('items') // Change to 'items' or 'equipment_catalog'
      .select('*')
      .order('name');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Restock endpoint
app.post('/api/catalog', async (req, res) => {
  try {
    const { sku, name, category, quantity } = req.body;
    
    const { data: existing } = await supabase
      .from('items') // Match table name
      .select('*')
      .eq('sku', sku)
      .maybeSingle();

    if (existing) {
      const { data, error } = await supabase
        .from('items')
        .update({
          total_quantity: Number(existing.total_quantity || 0) + Number(quantity),
          available_quantity: Number(existing.available_quantity || 0) + Number(quantity)
        })
        .eq('id', existing.id)
        .select()
        .single();
      if (error) throw error;
      return res.json(data);
    } else {
      const { data, error } = await supabase
        .from('items')
        .insert([{
          sku,
          name,
          category,
          total_quantity: Number(quantity),
          available_quantity: Number(quantity)
        }])
        .select()
        .single();
      if (error) throw error;
      return res.json(data);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Submit Requisition from Mobile App
app.post('/api/requisitions', async (req, res) => {
  try {
    const { borrower_id, borrower_name, item_id, item_name, quantity } = req.body;

    const { data, error } = await supabase
      .from('requisitions')
      .insert([{
        borrower_id,
        borrower_name,
        item_id,
        item_name,
        quantity: parseInt(quantity, 10) || 1,
        status: 'pending',
        requested_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    console.error('Error creating requisition:', err);
    res.status(500).json({ error: err.message });
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
