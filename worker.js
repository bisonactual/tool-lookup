/**
 * Hackspace Manchester Tool Lookup - Cloudflare Worker
 *
 * Endpoints:
 *   POST /api/login       { email, password } → { token }
 *   GET  /api/tool/:slug  Authorization: Bearer <token> → tool data JSON
 */

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
}

async function handleRequest(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: CORS })
  }

  const url = new URL(request.url)

  if (url.pathname === '/api/login' && request.method === 'POST') {
    return handleLogin(request)
  }

  const toolMatch = url.pathname.match(/^\/api\/tool\/(.+)$/)
  if (toolMatch && request.method === 'GET') {
    return handleTool(request, toolMatch[1])
  }

  return json({ error: 'Not found' }, 404)
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

async function handleLogin(request) {
  let email, password
  try {
    ;({ email, password } = await request.json())
  } catch {
    return json({ error: 'Invalid request body' }, 400)
  }

  if (!email || !password) {
    return json({ error: 'Email and password are required' }, 400)
  }

  try {
    // 1. Fetch login page to get a fresh CSRF token and session cookie
    const loginPageRes = await fetch('https://members.hacman.org.uk/login', {
      headers: { 'User-Agent': 'Mozilla/5.0', Accept: 'text/html' },
    })
    const loginPageHtml = await loginPageRes.text()

    const csrfMatch = loginPageHtml.match(/name="_token"\s+value="([^"]+)"/)
    if (!csrfMatch) return json({ error: 'Could not reach Hackspace login page' }, 502)
    const csrfToken = csrfMatch[1]

    // Cloudflare Workers may return multiple Set-Cookie headers — collect all of them
    const initialCookies = getAllCookies(loginPageRes.headers)
    const initialSession = extractSessionCookie(initialCookies)

    // 2. Submit the login form
    const loginRes = await fetch('https://members.hacman.org.uk/session', {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0',
        Referer: 'https://members.hacman.org.uk/login',
        Cookie: initialSession ? `laravel_session=${initialSession}` : '',
      },
      body: new URLSearchParams({ _token: csrfToken, email, password }).toString(),
    })

    const loginCookies = getAllCookies(loginRes.headers)
    const sessionToken = extractSessionCookie(loginCookies)

    if (!sessionToken) {
      return json({ error: 'Invalid email or password' }, 401)
    }

    // 3. Verify the token is actually authenticated by hitting /account
    const verifyRes = await fetch('https://members.hacman.org.uk/account', {
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0',
        Cookie: `laravel_session=${sessionToken}`,
      },
    })

    // If we got redirected back to /login, credentials were wrong
    if (verifyRes.url.includes('/login')) {
      return json({ error: 'Invalid email or password' }, 401)
    }

    return json({ token: sessionToken })
  } catch (e) {
    return json({ error: `Login failed: ${e.message}` }, 500)
  }
}

// ---------------------------------------------------------------------------
// Tool lookup
// ---------------------------------------------------------------------------

async function handleTool(request, slug) {
  const token = getBearerToken(request)
  if (!token) return json({ error: 'Not authenticated' }, 401)

  // Sanitise slug — only allow URL-safe characters
  if (!/^[a-z0-9_-]+$/i.test(slug)) {
    return json({ error: 'Invalid tool identifier' }, 400)
  }

  try {
    const equipRes = await fetch(`https://members.hacman.org.uk/equipment/${slug}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0',
        Cookie: `laravel_session=${token}`,
      },
    })

    if (equipRes.status === 404) return json({ error: 'Tool not found' }, 404)

    // If we got redirected to the login page the session has expired
    if (equipRes.url.includes('/login')) {
      return json({ error: 'Session expired' }, 401)
    }

    const html = await equipRes.text()
    const data = parseEquipmentPage(html, slug)
    return json(data)
  } catch (e) {
    return json({ error: `Could not fetch tool data: ${e.message}` }, 500)
  }
}

// ---------------------------------------------------------------------------
// HTML parser
// ---------------------------------------------------------------------------

function parseEquipmentPage(html, slug) {
  // Machine name
  const nameMatch = html.match(/<h2>([^<]+)<\/h2>/)
  const name = nameMatch ? nameMatch[1].trim() : slug

  // Induction / access code block
  // e.g. "You have been inducted and can use this equipment"
  //      "Access code: 481"
  const inducted = /You have been inducted/i.test(html)
  const accessCodeMatch = html.match(/Access code:\s*(\w+)/i)
  const accessCode = accessCodeMatch ? accessCodeMatch[1] : null

  // Induction booking link (only present when NOT inducted)
  const bookingMatch = html.match(/href="(https:\/\/members\.hacman\.org\.uk\/equipment\/[^"]+)"[^>]*>Book induction/i)
  const bookingLink = bookingMatch
    ? bookingMatch[1]
    : `https://members.hacman.org.uk/equipment/${slug}`

  // PPE images → human-readable names + image URLs
  const ppeMatches = [...html.matchAll(/\/img\/ppe\/([^"'>\s]+)/gi)]
  const ppe = [...new Set(ppeMatches.map(m => m[1]))].map(filename => ({
    label: filename
      .replace(/\.(jpg|png|jpeg|gif|webp)$/i, '')
      .replace(/[-_]/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase()),
    imageUrl: `https://members.hacman.org.uk/img/ppe/${filename}`,
  }))

  // Documentation link
  const docMatch = html.match(/href="(https:\/\/docs\.hacman\.org\.uk\/[^"]+)"/)
  const docsLink = docMatch ? docMatch[1] : null

  // tool-info__detail key/value pairs
  const toolInfo = extractToolInfo(html)

  return {
    name,
    slug,
    inducted,
    accessCode,
    bookingLink,
    ppe,
    docsLink,
    loneWorking: toolInfo['Lone working allowed?'] ?? toolInfo['loneWorking'] ?? null,
    toolWorking: toolInfo['Tool working?'] ?? toolInfo['toolWorking'] ?? null,
    location: toolInfo['Lives in'] ?? toolInfo['location'] ?? null,
  }
}

/**
 * Extract all key→value pairs from .tool-info__detail blocks.
 * Returns e.g. { "Lone working allowed?": "🔴 No lone working", "Tool working?": "🟢 Yes", ... }
 */
function extractToolInfo(html) {
  const result = {}

  // Try splitting on the detail class (handles both single and double quotes)
  const splitToken = html.includes('tool-info__detail')
    ? 'tool-info__detail'
    : null

  if (!splitToken) return result

  const blocks = html.split(splitToken)
  for (const block of blocks.slice(1)) {
    // Match key and value — use loose patterns to handle varying whitespace/quotes
    const keyMatch = block.match(/tool-info__key[^>]*>([\s\S]*?)<\/div>/i)
    const valMatch = block.match(/tool-info__value[^>]*>([\s\S]*?)<\/div>/i)
    if (keyMatch && valMatch) {
      const key = stripTags(keyMatch[1]).trim()
      const val = stripTags(valMatch[1]).trim()
      if (key && val) result[key] = val
    }
  }

  // If split approach found nothing, fall back to direct regex on known fields
  if (Object.keys(result).length === 0) {
    const fields = [
      ['loneWorking',  /Lone working allowed\?[\s\S]{1,300}?tool-info__value[^>]*>([\s\S]{1,100}?)<\/div>/i],
      ['toolWorking',  /Tool working\?[\s\S]{1,300}?tool-info__value[^>]*>([\s\S]{1,100}?)<\/div>/i],
      ['location',     /Lives in[\s\S]{1,300}?tool-info__value[^>]*>([\s\S]{1,100}?)<\/div>/i],
    ]
    for (const [key, re] of fields) {
      const m = html.match(re)
      if (m) result[key] = stripTags(m[1]).trim()
    }
    return result
  }

  return result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Cloudflare Workers can return multiple Set-Cookie headers.
 * headers.get() only returns the first one, so we join all values
 * into a single string that extractSessionCookie can search through.
 */
function getAllCookies(headers) {
  // getAll is available in Cloudflare Workers for set-cookie specifically
  if (typeof headers.getAll === 'function') {
    return headers.getAll('set-cookie').join('; ')
  }
  return headers.get('set-cookie') || ''
}

function extractSessionCookie(setCookieHeader) {
  const m = setCookieHeader.match(/laravel_session=([^;,\s]+)/)
  return m ? m[1] : null
}

function getBearerToken(request) {
  const auth = request.headers.get('Authorization') || ''
  const m = auth.match(/^Bearer\s+(.+)$/i)
  return m ? m[1] : null
}

function stripTags(str) {
  return str.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  })
}
