// index.js
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { KJUR } from 'jsrsasign';
import { z } from 'zod';
import fetch from 'node-fetch';
import { getZak } from './zoomAuth.js';

dotenv.config();
const app = express();
const port = process.env.PORT || 4000;

// ========== Safety checks ==========
['ZOOM_MEETING_SDK_KEY','ZOOM_MEETING_SDK_SECRET','ADALO_API_KEY','ADALO_COLLECTION_ID']
  .forEach((k) => {
    if (!process.env[k]) {
      console.error(`Missing env var: ${k}`);
      process.exit(1);
    }
  });

// ========== Security middleware ==========
app.use(helmet());

// CORS allowlist
const allowedOrigins = (process.env.CORS_ALLOWLIST || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  methods: ['POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json({ limit: '32kb' }));

// Rate limiting (per IP)
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 min
  max: 60,                  // 60 requests / 10 min
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ========== Schema ==========
const SignSchema = z.object({
  uuid: z.string().min(10),              // Adalo user UUID
  meetingNumber: z.union([z.string(), z.number()]),
  videoWebRtcMode: z.number().int().min(0).max(1).default(1),
});

// ========== Adalo lookup ==========
async function getUserByUUID(uuid) {
  const url = `https://api.adalo.com/v0/apps/${process.env.ADALO_APP_ID}/collections/${process.env.ADALO_COLLECTION_ID}?filters[UUID]=${uuid}`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${process.env.ADALO_API_KEY}`,
      'Content-Type': 'application/json',
    },
  });
  if (!res.ok) {
    console.error('Adalo lookup failed', await res.text());
    return null;
  }
  const data = await res.json();
  if (!data.records || data.records.length === 0) return null;

  const user = data.records[0];
  return {
    role: user.Role,                          // int: 0 attendee, 1 host
    zoomEmail: user.ZoomEmail || null,        // needed for ZAK if host
    allowedMeetings: user.AllowedMeetings || [] // array of meeting numbers
  };
}

// ========== Route ==========
app.post('/sign', async (req, res) => {
  try {
    const parsed = SignSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid body', details: parsed.error.issues });
    }

    const { uuid, meetingNumber, videoWebRtcMode } = parsed.data;
    const user = await getUserByUUID(uuid);

    if (!user) return res.status(401).json({ error: 'Unknown user' });

    const mn = String(meetingNumber);
    if (!user.allowedMeetings.map(String).includes(mn)) {
      return res.status(403).json({ error: 'User not allowed for this meeting' });
    }

    const role = Number(user.role) === 1 ? 1 : 0;

    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + (process.env.SIGN_EXP_SECONDS ? parseInt(process.env.SIGN_EXP_SECONDS) : 3600);

    const oHeader = { alg: 'HS256', typ: 'JWT' };
    const oPayload = {
      appKey: process.env.ZOOM_MEETING_SDK_KEY,
      sdkKey: process.env.ZOOM_MEETING_SDK_KEY,
      mn,
      role,
      iat,
      exp,
      tokenExp: exp,
      video_webrtc_mode: videoWebRtcMode,
    };

    const signature = KJUR.jws.JWS.sign(
      'HS256',
      JSON.stringify(oHeader),
      JSON.stringify(oPayload),
      process.env.ZOOM_MEETING_SDK_SECRET
    );

    let zak = null;
    if (role === 1 && user.zoomEmail) {
      zak = await getZak(user.zoomEmail);
    }

    return res.json({
      signature,
      sdkKey: process.env.ZOOM_MEETING_SDK_KEY,
      ...(zak ? { zak } : {}),
    });
  } catch (err) {
    console.error('Sign error:', err.message || err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(port, () => {
  console.log(`Auth server listening on ${port}`);
});
