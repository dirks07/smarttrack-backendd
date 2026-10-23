import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const app = express();
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization']
}));
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || ''
);

// Email dispatch via Brevo REST API with strict error surfacing
async function sendActivationEmail(recipientEmail, recipientName, token, role) {
  const apiKey = process.env.BREVO_API_KEY;
  if (!apiKey) {
    throw new Error('BREVO_API_KEY is missing in Render environment variables.');
  }

  const backendUrl = process.env.APP_URL || 'https://smarttrack-backendd.onrender.com';
  const activationUrl = `${backendUrl}/api/auth/activate?token=${token}&role=${role}`;
  const senderEmail = process.env.SENDER_EMAIL || 'dirkshaned@gmail.com';

  console.log(`Sending Brevo email to ${recipientEmail} from ${senderEmail}...`);

  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': apiKey.trim(),
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      sender: { name: 'CDM SmartTrack', email: senderEmail.trim() },
      to: [{ email: recipientEmail.trim(), name: recipientName.trim() }],
      subject: 'Activate Your CDM SmartTrack Account',
      htmlContent: `
        <div style="background:#090d16;color:#ffffff;padding:32px;font-family:sans-serif;border-radius:12px;max-width:480px;margin:auto;">
          <h2 style="color:#10b981;margin-bottom:8px;">CDM SMARTTRACK</h2>
          <p style="color:#94a3b8;font-size:14px;margin-bottom:20px;">Equipment & Asset Management System</p>
          <p style="font-size:15px;color:#f1f5f9;">Hello <strong>${recipientName}</strong>,</p>
          <p style="color:#94a3b8;font-size:14px;line-height:1.5;">Click below to verify your email and activate your account:</p>
          <div style="margin:24px 0;">
            <a href="${activationUrl}" style="background:#10b981;color:#022c22;padding:12px 24px;border-radius:6px;font-weight:bold;text-decoration:none;display:inline-block;">Activate Account</a>
          </div>
          <p style="color:#64748b;font-size:12px;">Link: ${activationUrl}</p>
        </div>
      `
    })
  });

  const resText = await response.text();
  let result;
  try {
    result = JSON.parse(resText);
  } catch (e) {
    result = { raw: resText };
  }

  if (!response.ok) {
    console.error('Brevo API Error:', result);
    throw new Error(result.message || 'Brevo rejected the email dispatch. Verify that your sender email is authorized in Brevo.');
  }

  console.log('Brevo message sent successfully. ID:', result.messageId);
  return result;
}

app.get('/', (req, res) => {
  res.send('SmartTrack API is live and operational.');
});

// ==========================================
// AUTHENTICATION & ACTIVATION
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
      role = 'borrower'
    } = req.body;

    const resolvedName = (fullName || full_name || '').trim();
    const resolvedStaffId = (staffId || staff_id || '').trim();
    const cleanEmail = (email || '').trim().toLowerCase();
    const cleanPassword = (password || '').trim();
    const resolvedDept = department || (role === 'admin' ? 'Property Custodian' : 'Student');

    if (!cleanEmail || !cleanPassword || !resolvedName) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    if (role === 'admin') {
      const { data: existing } = await supabase
        .from('profiles')
        .select('id, email, staff_id')
        .or(`email.ilike.${cleanEmail}${resolvedStaffId ? `,staff_id.eq.${resolvedStaffId}` : ''}`)
        .maybeSingle();

      if (existing) {
        return res.status(400).json({ error: 'An admin with this email or Staff ID already exists.' });
      }

      const { data, error } = await supabase
        .from('profiles')
        .insert([{
          full_name: resolvedName,
          staff_id: resolvedStaffId || null,
          email: cleanEmail,
          password_hash: cleanPassword,
          department: resolvedDept,
          role: 'admin',
          is_verified: false
        }])
        .select()
        .single();

      if (error) throw error;

      const token = jwt.sign(
        { id: data.id, role: 'admin' },
        process.env.JWT_SECRET || 'smarttrack-secret-key',
        { expiresIn: '1d' }
      );

      try {
        await sendActivationEmail(cleanEmail, resolvedName, token, 'admin');
      } catch (mailErr) {
        console.error('Mail send error:', mailErr.message);
      }

      return res.status(201).json({
        message: 'Registration successful! An activation link has been sent to your email.'
      });
    } else {
      const { data: existing } = await supabase
        .from('borrowers')
        .select('id, email, staff_id')
        .or(`email.ilike.${cleanEmail}${resolvedStaffId ? `,staff_id.eq.${resolvedStaffId}` : ''}`)
        .maybeSingle();

      if (existing) {
        return res.status(400).json({ error: 'A borrower with this email or ID is already registered.' });
      }

      const insertPayload = {
        full_name: resolvedName,
        email: cleanEmail,
        password: cleanPassword,
        department: resolvedDept,
        is_verified: false
      };
      if (resolvedStaffId) insertPayload.staff_id = resolvedStaffId;

      const { data, error } = await supabase
        .from('borrowers')
        .insert([insertPayload])
        .select()
        .single();

      if (error) throw error;

      const token = jwt.sign(
        { id: data.id, role: 'borrower' },
        process.env.JWT_SECRET || 'smarttrack-secret-key',
        { expiresIn: '1d' }
      );

      try {
        await sendActivationEmail(cleanEmail, resolvedName, token, 'borrower');
      } catch (mailErr) {
        console.error('Mail send error:', mailErr.message);
      }

      return res.status(201).json({
        message: 'Registration successful! An activation link has been sent to your email.'
      });
    }
  } catch (err) {
    console.error('Registration handler error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

// Email Activation Link Handler
app.get('/api/auth/activate', async (req, res) => {
  try {
    const { token, role } = req.query;
    if (!token) return res.status(400).send('Invalid or missing activation token.');

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'smarttrack-secret-key');
    const table = role === 'admin' ? 'profiles' : 'borrowers';

    const { error } = await supabase
      .from(table)
      .update({ is_verified: true })
      .eq('id', decoded.id);

    if (error) throw error;

    res.send(`
      <div style="background:#090d16;color:#ffffff;padding:40px;text-align:center;font-family:sans-serif;height:100vh;">
        <h1 style="color:#10b981;">Account Activated!</h1>
        <p style="color:#cbd5e1;font-size:16px;">Your account has been successfully verified. You can now return to the app or admin workstation and sign in.</p>
      </div>
    `);
  } catch (err) {
    res.status(400).send(`
      <div style="background:#090d16;color:#ffffff;padding:40px;text-align:center;font-family:sans-serif;height:100vh;">
        <h1 style="color:#ef4444;">Activation Failed</h1>
        <p style="color:#cbd5e1;">The activation link is invalid or has expired.</p>
      </div>
    `);
  }
});

// Login (Enforces is_verified check)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, identifier, staff_id, staffId, password } = req.body;
    const loginIdent = (email || identifier || staff_id || staffId || '').trim().toLowerCase();
    const cleanPassword = (password || '').trim();

    if (!loginIdent || !cleanPassword) {
      return res.status(400).json({ error: 'Email/ID and password are required' });
    }

    // 1. Check profiles (Admin)
    const { data: adminUser } = await supabase
      .from('profiles')
      .select('*')
      .or(`email.ilike.${loginIdent},staff_id.ilike.${loginIdent}`)
      .maybeSingle();

    if (adminUser) {
      const storedHash = adminUser.password_hash || '';
      let isValid = cleanPassword === storedHash;
      if (!isValid && storedHash.startsWith('$2')) {
        isValid = await bcrypt.compare(cleanPassword, storedHash);
      }
      if (isValid) {
        if (!adminUser.is_verified) {
          return res.status(403).json({
            error: 'Account not verified. Please check your email to activate your account.'
          });
        }
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

    // 2. Check borrowers (Student / Faculty)
    const { data: borrowerUser } = await supabase
      .from('borrowers')
      .select('*')
      .or(`email.ilike.${loginIdent},staff_id.ilike.${loginIdent}`)
      .maybeSingle();

    if (borrowerUser) {
      const storedPass = borrowerUser.password || '';
      let isValid = cleanPassword === storedPass;
      if (!isValid && storedPass.startsWith('$2')) {
        isValid = await bcrypt.compare(cleanPassword, storedPass);
      }
      if (isValid) {
        if (!borrowerUser.is_verified) {
          return res.status(403).json({
            error: 'Account not verified. Please check your email to activate your account.'
          });
        }
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
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

// ==========================================
// CATALOG & RESTOCK (items table)
// ==========================================
app.get('/api/catalog', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('items')
      .select('*')
      .order('name');

    if (error) throw error;
    const normalized = (data || []).map(item => ({
      ...item,
      title: item.name,
      equipmentName: item.name,
      available: item.available_quantity,
      total: item.total_quantity
    }));
    res.json(normalized);
  } catch (err) {
    console.error('Catalog fetch error:', err);
    res.status(500).json({ error: err.message });
  }
});

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
    console.error('Restock API error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// REQUISITION ROUTES
// ==========================================

// 1. Submit a requisition ticket (From Mobile App)
app.post('/api/requisitions', async (req, res) => {
  try {
    const { borrower_id, borrower_name, item_id, equipment_id, item_name, quantity, purpose } = req.body;

    const bName = (borrower_name && borrower_name.trim()) ? borrower_name.trim() : 'Student Borrower';
    const bId = (borrower_id && borrower_id.trim()) ? borrower_id.trim() : 'STU-001';
    const resolvedItem = item_name || 'Equipment Item';
    const resolvedItemId = String(item_id || equipment_id || '');
    const ticketNo = 'ST-' + Math.floor(100000 + Math.random() * 900000);

    const insertPayload = {
      ticket_no: ticketNo,
      borrower_id: bId,
      borrower_name: bName,
      item_name: resolvedItem,
      quantity: parseInt(quantity, 10) || 1,
      purpose: purpose || 'Academic Project',
      status: 'pending',
      requested_at: new Date().toISOString()
    };

    if (resolvedItemId) {
      insertPayload.item_id = resolvedItemId;
      insertPayload.equipment_id = resolvedItemId;
    }

    const { data, error } = await supabase
      .from('requisitions')
      .insert([insertPayload])
      .select()
      .single();

    if (error) {
      console.error('Supabase Requisition Insert Error:', error);
      return res.status(500).json({ error: error.message });
    }

    res.status(201).json(data);
  } catch (err) {
    console.error('Requisition creation error:', err);
    res.status(500).json({ error: err.message });
  }
});

// 2. Fetch all requisitions (For Webapp Admin Approval Desk)
app.get('/api/requisitions', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('requisitions')
      .select('*')
      .order('requested_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Fetch requisitions error:', err);
    res.status(500).json({ error: err.message });
  }
});

// 3. Fetch borrower-specific tickets (Supports matching by borrower_id OR borrower_name)
app.get('/api/requisitions/borrower/:identifier', async (req, res) => {
  try {
    const rawId = decodeURIComponent(req.params.identifier).trim();

    const { data, error } = await supabase
      .from('requisitions')
      .select('*')
      .or(`borrower_name.ilike.%${rawId}%,borrower_id.eq.${rawId}`)
      .order('requested_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Fetch borrower tickets error:', err);
    res.status(500).json({ error: err.message });
  }
});

// 4. Update Requisition Status (Approve, Reject, Claim, Return)
app.patch('/api/requisitions/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const updatePayload = { status };
    if (status === 'claimed') {
      updatePayload.dispatched_at = new Date().toISOString();
    } else if (status === 'returned') {
      updatePayload.returned_at = new Date().toISOString();
    }

    // 1. Update the requisition status
    const { data, error } = await supabase
      .from('requisitions')
      .update(updatePayload)
      .eq('id', id)
      .select()
      .single();

    if (error) {
      console.error('Requisition status update error:', error);
      return res.status(500).json({ error: error.message });
    }

    // 2. Adjust item quantity safely without breaking the dispatch flow
    try {
      if (data && data.item_name) {
        const { data: itemData } = await supabase
          .from('items')
          .select('*')
          .ilike('name', data.item_name.trim())
          .maybeSingle();

        if (itemData) {
          const qtyDelta = parseInt(data.quantity, 10) || 1;
          let newQty = itemData.available_quantity;

          if (status === 'claimed') {
            newQty = Math.max(0, Number(itemData.available_quantity || 0) - qtyDelta);
          } else if (status === 'returned') {
            newQty = Math.min(
              Number(itemData.total_quantity || 0),
              Number(itemData.available_quantity || 0) + qtyDelta
            );
          }

          await supabase
            .from('items')
            .update({ available_quantity: newQty })
            .eq('id', itemData.id);
        }
      }
    } catch (stockErr) {
      console.warn('Inventory quantity adjust warning (non-fatal):', stockErr.message);
    }

    return res.json(data);
  } catch (err) {
    console.error('Patch status fatal error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SmartTrack Server active on port ${PORT}`));