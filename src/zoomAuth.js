// src/zoomAuth.js

let cachedToken = null
let cachedExpiry = 0

/**
 * Get a valid Zoom OAuth access token.
 */
export async function getZoomAccessToken() {
  const now = Math.floor(Date.now() / 1000)

  if (cachedToken && now < cachedExpiry - 60) {
    return cachedToken // still valid
  }

  const tokenUrl = 'https://zoom.us/oauth/token'
  const authString = Buffer.from(`${process.env.ZOOM_CLIENT_ID}:${process.env.ZOOM_CLIENT_SECRET}`).toString('base64')

  const response = await fetch(`${tokenUrl}?grant_type=account_credentials&account_id=${process.env.ZOOM_ACCOUNT_ID}`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${authString}`
    }
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(`Failed to fetch Zoom OAuth token: ${response.status} ${text}`)
  }

  const data = await response.json()
  cachedToken = data.access_token
  cachedExpiry = now + data.expires_in

  return cachedToken
}

export async function getZak(userId = 'me') {
  const accessToken = await getZoomAccessToken()

  const response = await fetch(`https://api.zoom.us/v2/users/${userId}/token?type=zak`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    }
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(`Failed to fetch ZAK: ${response.status} ${text}`)
  }

  const data = await response.json()
  return data.token
}
