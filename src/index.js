// index.js
import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import { KJUR } from 'jsrsasign'
import { z } from 'zod'
import fetch from 'node-fetch'
import { getZak } from './zoomAuth.js'

dotenv.config()
const app = express()
app.set('trust proxy', 1)
const port = process.env.PORT || 4000

// ========== Safety checks ==========
;['ZOOM_MEETING_SDK_KEY', 'ZOOM_MEETING_SDK_SECRET', 'ADALO_API_KEY', 'ADALO_COLLECTION_ID'].forEach((k) => {
  if (!process.env[k]) {
    console.error(`Missing env var: ${k}`)
    process.exit(1)
  }
})

// ========== Security middleware ==========
app.use(helmet())

// CORS allowlist
const allowedOrigins = (process.env.CORS_ALLOWLIST || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true)
      return cb(new Error('Not allowed by CORS'))
    },
    methods: ['POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
  })
)

app.use(express.json({ limit: '32kb' }))

// Rate limiting (per IP)
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 min
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
})
app.use(limiter)

// ========== Schema ==========
const SignSchema = z.object({
  uuid: z.string().min(10), // Adalo user UUID
  meetingNumber: z.union([z.string(), z.number()]),
  videoWebRtcMode: z.number().int().min(0).max(1).default(1)
})

// ========== Adalo lookup ==========
async function getUserByUUID(uuid) {
  const safeUUID = String(uuid).trim()
  console.log(`[Adalo] Fetching user with UUID=${safeUUID}`)

  const url =
    `https://api.adalo.com/v0/apps/${process.env.ADALO_APP_ID}` +
    `/collections/${process.env.ADALO_COLLECTION_ID}` +
    `?filterKey=UUID&filterValue=${encodeURIComponent(safeUUID)}&limit=1`

  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${process.env.ADALO_API_KEY}`,
      'Content-Type': 'application/json'
    }
  })

  if (!res.ok) {
    console.error('[Adalo] Lookup failed:', await res.text())
    return null
  }

  const data = await res.json().catch(() => ({}))
  if (!data.records || data.records.length === 0) {
    console.warn(`[Adalo] No record found for UUID=${safeUUID}`)
    return null
  }

  const user = data.records[0]
  console.log('[Adalo] Relevant record:', {
    id: user.id,
    UUID: user.UUID,
    Email: user.Email,
    Role: user.Role,
    ZoomEmail: user.ZoomEmail
  })

  // ✅ Only use Role (ignore AppRole)
  const role = user.Role !== undefined && Number(user.Role) === 1 ? 1 : 0
  const zoomEmail = user.ZoomEmail && String(user.ZoomEmail).trim() ? String(user.ZoomEmail).trim() : null

  console.log(`[Adalo] Normalized role=${role}, zoomEmailPresent=${!!zoomEmail}`)

  return { role, zoomEmail }
}

// ========== Route ==========
app.post('/sign', async (req, res) => {
  try {
    console.log('[SIGN] Incoming body:', req.body)

    const parsed = SignSchema.safeParse(req.body)
    if (!parsed.success) {
      console.error('[SIGN] Schema validation failed:', parsed.error.issues)
      return res.status(400).json({ error: 'Invalid body', details: parsed.error.issues })
    }

    const { uuid, meetingNumber, videoWebRtcMode } = parsed.data
    console.log(
      `[SIGN] Parsed request: uuid=${uuid}, meetingNumber=${meetingNumber}, videoWebRtcMode=${videoWebRtcMode}`
    )

    const user = await getUserByUUID(uuid)
    if (!user) {
      console.warn('[SIGN] Unknown user for uuid=', uuid)
      return res.status(401).json({ error: 'Unknown user' })
    }

    let role = user.role
    let zak = null
    const mn = String(meetingNumber)

    console.log(`[SIGN] Starting role=${role}, zoomEmail=${user.zoomEmail}`)

    const iat = Math.floor(Date.now() / 1000)
    const exp = iat + (process.env.SIGN_EXP_SECONDS ? parseInt(process.env.SIGN_EXP_SECONDS) : 3600)

    const oHeader = { alg: 'HS256', typ: 'JWT' }
    let oPayload = {
      appKey: process.env.ZOOM_MEETING_SDK_KEY,
      sdkKey: process.env.ZOOM_MEETING_SDK_KEY,
      mn,
      role,
      iat,
      exp,
      tokenExp: exp,
      video_webrtc_mode: videoWebRtcMode
    }

    let signature = KJUR.jws.JWS.sign(
      'HS256',
      JSON.stringify(oHeader),
      JSON.stringify(oPayload),
      process.env.ZOOM_MEETING_SDK_SECRET
    )

    // Only fetch ZAK if DB says host
    if (role === 1 && user.zoomEmail) {
      console.log(`[SIGN] Attempting ZAK fetch for email=${user.zoomEmail}`)
      try {
        const maybeZak = await getZak(user.zoomEmail)
        console.log('[SIGN] getZak result:', maybeZak)

        if (typeof maybeZak === 'string' && maybeZak.trim() !== '') {
          zak = maybeZak
          console.log('[SIGN] ✅ ZAK assigned')
        } else {
          console.warn('[SIGN] ❌ Empty/invalid ZAK, demoting to attendee')
          role = 0
          zak = null
        }
      } catch (err) {
        console.error(`[SIGN] ZAK fetch failed for ${user.zoomEmail}:`, err)
        role = 0
        zak = null
      }

      // regenerate signature if demoted
      if (role === 0) {
        oPayload.role = 0
        signature = KJUR.jws.JWS.sign(
          'HS256',
          JSON.stringify(oHeader),
          JSON.stringify(oPayload),
          process.env.ZOOM_MEETING_SDK_SECRET
        )
        console.log('[SIGN] Signature regenerated as attendee')
      }
    } else {
      console.log('[SIGN] Skipping ZAK fetch (role not host or no zoomEmail)')
    }

    // Build payload (no zak by default)
    const payload = {
      signature,
      sdkKey: process.env.ZOOM_MEETING_SDK_KEY
    }

    if (role === 1 && typeof zak === 'string' && zak.trim() !== '') {
      payload.zak = zak
      console.log('[SIGN] Returning ZAK in payload')
    } else {
      console.log('[SIGN] No ZAK in payload')
    }

    console.log(`[SIGN RESPONSE] uuid=${uuid}, finalRole=${role}, hasZak=${!!zak}`)
    return res.json(JSON.parse(JSON.stringify(payload)))
  } catch (err) {
    console.error('[SIGN] Error:', err.message || err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

app.listen(port, () => {
  console.log(`Auth server listening on ${port}`)
})
