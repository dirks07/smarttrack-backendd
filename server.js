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

// Health check
app.get('/', (req, res) => {
  res.send('SmartTrack API is live and operational.');
});

// ==========================================
// 1. REGISTRATION (Admin & Borrower)
// ==========================================
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

    const resolvedName = (fullName || full_name || '').trim();
    const resolvedStaffId = (staffId || staff_id || '').trim();
    const cleanEmail = (email || '').trim().toLowerCase();
    const cleanPassword = (password || '').trim();
    const resolvedDept = department || (role === 'admin' ? 'Property Custodian' : 'Student');

    if (!cleanEmail || !cleanPassword || !resolvedName) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    if (role === 'admin') {
      // Check if email or staff_id already exists in profiles
      const { data: existing } = await supabase
        .from('profiles')
        .select('id, email, staff_id')
        .or(`email.ilike.${cleanEmail}${resolvedStaffId ? `,staff_id.eq.${resolvedStaffId}` : ''}`)
        .maybeSingle();

      if (existing) {
        if (existing.email.toLowerCase() === cleanEmail) {
          return res.status(400).json({ error: 'An admin with this email is already registered. Please sign in.' });
        }
        return res.status(400).json({ error: `Staff ID "${resolvedStaffId}" is already registered. Use a different ID or sign in.` });
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
          is_verified: true
        }])
        .select()
        .single();

      if (error) throw error;
      return res.status(201).json({ message: 'Admin registered successfully!', profile: data });

    } else {
      // Borrower flow
      const { data: existing } = await supabase
        .from('borrowers')
        .select('id, email, staff_id')
        .or(`email.ilike.${cleanEmail}${resolvedStaffId ? `,staff_id.eq.${resolvedStaffId}` : ''}`)
        .maybeSingle();

      if (existing) {
        return res.status(400).json({ error: 'A borrower with this email or ID is already registered. Please sign in.' });
      }

      // Insert without relying on 'role' column to prevent PostgREST cache issues
      const insertPayload = {
        full_name: resolvedName,
        email: cleanEmail,
        password: cleanPassword,
        department: resolvedDept,
        is_verified: true
      };
      if (resolvedStaffId) insertPayload.staff_id = resolvedStaffId;

      const { data, error } = await supabase
        .from('borrowers')
        .insert([insertPayload])
        .select()
        .single();

      if (error) throw error;
      return res.status(201).json({ message: 'Borrower registered successfully!', user: data });
    }
  } catch (err) {
    console.error('Registration handler error:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

// ==========================================
// 2. UNIFIED LOGIN (Admin & Borrower)
// ==========================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, identifier, staff_id, staffId, password } = req.body;
    const loginIdent = (email || identifier || staff_id || staffId || '').trim().toLowerCase();
    const cleanPassword = (password || '').trim();

    if (!loginIdent || !cleanPassword) {
      return res.status(400).json({ error: 'Identifier/email and password are required' });
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

    // 2. Check borrowers
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
// 3. CATALOG & RESTOCK (items table)
// ==========================================
app.get('/api/catalog', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('items')
      .select('*')
      .order('name');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
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
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 4. REQUISITIONS (Borrower Request -> Admin Desk)
// ==========================================
// Create requisition (Handles both camelCase and snake_case from Mobile)
app.post('/api/requisitions', async (req, res) => {
  try {
    const bId = req.body.borrower_id || req.body.borrowerId || null;
    const bName = req.body.borrower_name || req.body.borrowerName || 'Borrower';
    const iId = req.body.item_id || req.body.itemId || null;
    const iName = req.body.item_name || req.body.itemName || req.body.equipmentName || 'Equipment Item';
    const qty = parseInt(req.body.quantity, 10) || 1;

    const { data, error } = await supabase
      .from('requisitions')
      .insert([{
        borrower_id: bId,
        borrower_name: bName,
        item_id: iId,
        item_name: iName,
        quantity: qty,
        status: 'pending',
        requested_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    console.error('Requisition submission error:', err);
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

// Admin Approve / Reject / Return status update
app.patch('/api/requisitions/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const updatePayload = { status: status.toLowerCase() };
    if (status.toLowerCase() === 'claimed' || status.toLowerCase() === 'approved') {
      updatePayload.dispatched_at = new Date().toISOString();
    } else if (status.toLowerCase() === 'returned') {
      updatePayload.returned_at = new Date().toISOString();
    }

    const { data, error } = await supabase
      .from('requisitions')
      .update(updatePayload)
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