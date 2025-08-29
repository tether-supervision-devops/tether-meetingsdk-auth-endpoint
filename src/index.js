import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import { KJUR } from 'jsrsasign'
import { inNumberArray, isBetween, isRequiredAllOrNone, validateRequest } from './validations.js'
import { getZak } from "./zoomAuth.js";

dotenv.config()
const app = express()
const port = process.env.PORT || 4000

app.use(express.json(), cors())
app.options('*', cors())

const propValidations = {
  role: inNumberArray([0, 1]),
  expirationSeconds: isBetween(1800, 172800),
  videoWebRtcMode: inNumberArray([0, 1])
}

const schemaValidations = [isRequiredAllOrNone(['meetingNumber', 'role'])]

const coerceRequestBody = (body) => ({
  ...body,
  ...['role', 'expirationSeconds', 'videoWebRtcMode'].reduce(
    (acc, cur) => ({ ...acc, [cur]: typeof body[cur] === 'string' ? parseInt(body[cur]) : body[cur] }),
    {}
  )
})

app.post("/", async (req, res) => {
  try {
    const requestBody = coerceRequestBody(req.body);
    const validationErrors = validateRequest(
      requestBody,
      propValidations,
      schemaValidations
    );

    if (validationErrors.length > 0) {
      return res.status(400).json({ errors: validationErrors });
    }

    const { meetingNumber, role, expirationSeconds, videoWebRtcMode } = requestBody;
    const iat = Math.floor(Date.now() / 1000);
    const exp = expirationSeconds ? iat + expirationSeconds : iat + 60 * 60 * 2;
    const oHeader = { alg: "HS256", typ: "JWT" };

    const oPayload = {
      appKey: process.env.ZOOM_MEETING_SDK_KEY,
      sdkKey: process.env.ZOOM_MEETING_SDK_KEY,
      mn: meetingNumber,
      role,
      iat,
      exp,
      tokenExp: exp,
      video_webrtc_mode: videoWebRtcMode,
    };

    const sHeader = JSON.stringify(oHeader);
    const sPayload = JSON.stringify(oPayload);
    const sdkJWT = KJUR.jws.JWS.sign(
      "HS256",
      sHeader,
      sPayload,
      process.env.ZOOM_MEETING_SDK_SECRET
    );

    // Fetch ZAK only for host (role = 1)
    let zakToken = null;
    if (role === 1) {
      zakToken = await getZak("me");
    }

    return res.json({
      signature: sdkJWT,
      sdkKey: process.env.ZOOM_MEETING_SDK_KEY,
      zak: zakToken,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.listen(port, () => console.log(`Zoom Meeting SDK Auth Endpoint Sample Node.js, listening on port ${port}!`))
