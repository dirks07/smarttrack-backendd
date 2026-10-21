import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const app = express();

// Comprehensive CORS middleware & preflight handling
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization']
}));
app.options('*', cors());

app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || ''
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

// Health Check
app.get('/', (req, res) => {
  res.send('SmartTrack API is live and operational.');
});

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

// Register Admin or Borrower
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
      const { data: existing } = await supabase
        .from('profiles')
        .select('id')
        .eq('email', cleanEmail)
        .maybeSingle();

      if (existing) {
        return res.status(400).json({ error: 'An admin with this email already exists.' });
      }

      const { data, error } = await supabase
        .from('profiles')
        .insert([{
          full_name: resolvedName,
          staff_id: resolvedStaffId,
          email: cleanEmail,
          password_hash: password,
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

// Unified Login for Admin (profiles) and Mobile (borrowers)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, identifier, staff_id, staffId, password } = req.body;
    const loginIdent = (email || identifier || staff_id || staffId || '').trim().toLowerCase();

    if (!loginIdent || !password) {
      return res.status(400).json({ error: 'Identifier/email and password are required' });
    }

    // 1. Check profiles (Admins / Custodians)
    const { data: adminUser } = await supabase
      .from('profiles')
      .select('*')
      .or(`email.ilike.${loginIdent},staff_id.ilike.${loginIdent}`)
      .maybeSingle();

    if (adminUser) {
      const storedHash = adminUser.password_hash || '';
      let isValid = password === storedHash;
      if (!isValid && storedHash.startsWith('$2')) {
        isValid = await bcrypt.compare(password, storedHash);
      }

      if (isValid) {
        const token = jwt.sign(
          { id: adminUser.id, role: adminUser.role || 'admin', email: adminUser.email },
          process.env.JWT_SECRET || 'smarttrack-secret-key',
          { expiresIn: '7d' }
        );
        return res.json({
          message: 'Admin login successful',
          token,
          user: adminUser,
          profile: adminUser
        });
      }
    }

    // 2. Check borrowers (Students / Faculty)
    const { data: borrowerUser } = await supabase
      .from('borrowers')
      .select('*')
      .or(`email.ilike.${loginIdent},staff_id.ilike.${loginIdent}`)
      .maybeSingle();

    if (borrowerUser) {
      const storedPass = borrowerUser.password || '';
      let isValid = password === storedPass;
      if (!isValid && storedPass.startsWith('$2')) {
        isValid = await bcrypt.compare(password, storedPass);
      }

      if (isValid) {
        const token = jwt.sign(
          { id: borrowerUser.id, role: 'borrower', email: borrowerUser.email },
          process.env.JWT_SECRET || 'smarttrack-secret-key',
          { expiresIn: '7d' }
        );
        return res.json({
          message: 'Borrower login successful',
          token,
          user: borrowerUser,
          profile: borrowerUser
        });
      }
    }

    return res.status(401).json({ error: 'Invalid credentials. Please verify your email/ID and password.' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err.message || 'Internal server error during login' });
  }
});

// ==========================================
// CATALOG & INVENTORY ROUTES (items table)
// ==========================================

// Get all equipment catalog items
app.get('/api/catalog', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('items')
      .select('*')
      .order('name');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Error fetching catalog:', err);
    res.status(500).json({ error: err.message });
  }
});

// Restock or add equipment to catalog
app.post('/api/catalog', async (req, res) => {
  try {
    const { sku, name, category, quantity } = req.body;
    const qty = parseInt(quantity, 10) || 1;
    const cleanSku = (sku || '').trim();

    const { data: existing } = await supabase
      .from('items')
      .select('*')
      .eq('sku', cleanSku)
      .maybeSingle();

    if (existing) {
      const { data, error } = await supabase
        .from('items')
        .update({
          total_quantity: Number(existing.total_quantity || 0) + qty,
          available_quantity: Number(existing.available_quantity || 0) + qty,
          updated_at: new Date().toISOString()
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
          sku: cleanSku,
          name: (name || '').trim(),
          category: category || 'Equipment',
          total_quantity: qty,
          available_quantity: qty
        }])
        .select()
        .single();

      if (error) throw error;
      return res.status(201).json(data);
    }
  } catch (err) {
    console.error('Error restocking item:', err);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// REQUISITION ROUTES
// ==========================================

// Submit requisition from Mobile App
app.post('/api/requisitions', async (req, res) => {
  try {
    const { borrower_id, borrower_name, item_id, item_name, quantity } = req.body;

    const { data, error } = await supabase
      .from('requisitions')
      .insert([{
        borrower_id,
        borrower_name: borrower_name || 'Borrower',
        item_id,
        item_name: item_name || 'Equipment',
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

// Fetch all requisitions for Admin Desk
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

// Update Requisition Status (Approve / Reject)
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