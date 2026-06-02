import { Hono, type Context } from 'hono';
import { cors } from 'hono/cors';
import { sign, verify } from 'hono/jwt';

type Bindings = {
  DB: D1Database;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  JWT_SECRET: string;
  GOOGLE_REDIRECT_URI?: string;
};

type Variables = {
  auth: AccessTokenPayload;
};

type JwtPayload = {
  sub: string;
  email: string;
  type: 'access' | 'refresh';
  exp: number;
};

type AccessTokenPayload = JwtPayload;

type OAuthStatePayload = {
  type: 'oauth_state';
  exp: number;
  redirectTo?: string;
};

type UserRow = {
  id: string;
  email: string;
  name: string;
  google_id: string;
  avatar_url: string | null;
  created_at: string;
  updated_at: string;
};

type CommitmentStatus = 'pending' | 'completed' | 'cancelled' | 'overdue';
type PaymentStatus = 'pending' | 'completed' | 'failed' | 'refunded';
type PaymentMethod = 'cash' | 'card' | 'bank_transfer' | 'digital_wallet';

type CommitmentRow = {
  id: string;
  user_id: string;
  title: string;
  description: string | null;
  amount: number | string;
  due_date: string | null;
  status: CommitmentStatus;
  category: string | null;
  created_at: string;
  updated_at: string;
  paid_amount?: number | string;
};

type PaymentRow = {
  id: string;
  commitment_id: string;
  amount: number | string;
  payment_date: string;
  method: PaymentMethod;
  status: PaymentStatus;
  reference: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
};

type GoogleTokenResponse = {
  access_token: string;
  expires_in: number;
  id_token?: string;
  refresh_token?: string;
  scope: string;
  token_type: string;
};

type GoogleUserInfo = {
  id: string;
  email: string;
  verified_email?: boolean;
  name: string;
  picture?: string;
};

class ApiError extends Error {
  status: number;
  details?: unknown;

  constructor(status: number, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

const commitmentStatuses: CommitmentStatus[] = ['pending', 'completed', 'cancelled', 'overdue'];
const paymentStatuses: PaymentStatus[] = ['pending', 'completed', 'failed', 'refunded'];
const paymentMethods: PaymentMethod[] = ['cash', 'card', 'bank_transfer', 'digital_wallet'];
type AppEnv = { Bindings: Bindings; Variables: Variables };
type AppContext = Context<AppEnv>;

const app = new Hono<AppEnv>();

async function authMiddleware(c: AppContext, next: () => Promise<void>) {
  const authorization = c.req.header('Authorization');
  if (!authorization || !authorization.startsWith('Bearer ')) {
    throw new ApiError(401, 'Missing bearer token');
  }

  const token = authorization.slice('Bearer '.length);
  const payload = await verifyJwt<JwtPayload>(token, c.env.JWT_SECRET);
  if (payload.type !== 'access') {
    throw new ApiError(401, 'Invalid access token');
  }

  c.set('auth', payload);
  await next();
}

app.use(
  '*',
  cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
  }),
);

app.onError((error) => {
  if (error instanceof ApiError) {
    return new Response(JSON.stringify({ error: { message: error.message, details: error.details } }), {
      status: error.status,
      headers: {
        'content-type': 'application/json; charset=utf-8',
      },
    });
  }

  console.error(error);
  return new Response(JSON.stringify({ error: { message: 'Internal server error' } }), {
    status: 500,
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
  });
});

app.get('/', (c) =>
  c.json({
    name: 'PayCycle API',
    version: '1.0.0',
    docs_url: `${new URL(c.req.url).origin}/api-docs`,
    openapi_url: `${new URL(c.req.url).origin}/api-json`,
  }),
);

app.get('/health', (c) =>
  c.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
  }),
);

app.get('/auth/google', async (c) => {
  ensureGoogleConfig(c.env);

  const redirectUri = getGoogleRedirectUri(c);
  const redirectTo = normalizeAppRedirectUri(c.req.query('redirect_to'));
  const state = await sign(
    {
      type: 'oauth_state',
      exp: getUnixTime() + 600,
      ...(redirectTo ? { redirectTo } : {}),
    } satisfies OAuthStatePayload,
    c.env.JWT_SECRET,
  );

  const params = new URLSearchParams({
    client_id: c.env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'consent',
    state,
  });

  return c.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/auth/google/callback', async (c) => {
  ensureGoogleConfig(c.env);

  const code = c.req.query('code');
  const state = c.req.query('state');

  if (!state) {
    throw new ApiError(400, 'Missing OAuth state');
  }

  const statePayload = await verifyJwt<OAuthStatePayload>(state, c.env.JWT_SECRET);
  if (statePayload.type !== 'oauth_state') {
    throw new ApiError(401, 'Invalid OAuth state');
  }

  const redirectTo = normalizeAppRedirectUri(statePayload.redirectTo);

  if (!code) {
    if (redirectTo) {
      return c.redirect(buildAppAuthErrorRedirect(redirectTo, 'Missing Google authorization code'));
    }

    throw new ApiError(400, 'Missing Google authorization code');
  }

  try {
    const googleTokens = await exchangeGoogleCode(c.env, code, getGoogleRedirectUri(c));
    const googleUser = await fetchGoogleUser(googleTokens.access_token);

    if (googleUser.verified_email === false) {
      throw new ApiError(403, 'Google account email is not verified');
    }

    const user = await upsertGoogleUser(c.env.DB, googleUser);
    const tokens = await issueAuthTokens(c.env.JWT_SECRET, user);
    const serializedUser = serializeUser(user);

    if (redirectTo) {
      return c.redirect(buildAppAuthSuccessRedirect(redirectTo, tokens, serializedUser));
    }

    return c.json(
      {
        ...tokens,
        user: serializedUser,
      },
      { status: 200 },
    );
  } catch (error) {
    if (redirectTo) {
      return c.redirect(buildAppAuthErrorRedirect(redirectTo, getPublicErrorMessage(error)));
    }

    throw error;
  }
});

app.post('/auth/refresh', async (c) => {
  const body = await readJsonBody(c);
  const refreshToken = requireString(body.refresh_token, 'refresh_token');
  const payload = await verifyJwt<JwtPayload>(refreshToken, c.env.JWT_SECRET);

  if (payload.type !== 'refresh') {
    throw new ApiError(401, 'Invalid refresh token');
  }

  const user = await dbFirst<UserRow>(c.env.DB, 'SELECT * FROM users WHERE id = ?', [payload.sub]);
  if (!user) {
    throw new ApiError(401, 'User not found for refresh token');
  }

  const tokens = await issueAuthTokens(c.env.JWT_SECRET, user);
  return c.json(
    {
      ...tokens,
      user: serializeUser(user),
    },
    { status: 200 },
  );
});

app.post('/auth/logout', (c) =>
  c.json({
    message: 'Logged out. Discard the access and refresh tokens on the client.',
  }),
);

app.use('/commitments/*', authMiddleware);
app.use('/payments/*', authMiddleware);

app.get('/commitments', async (c) => {
  const auth = c.get('auth');
  const cycle = getCurrentMonthlyCycle();
  const commitments = await dbAll<CommitmentRow>(
    c.env.DB,
    `
      SELECT
        c.*,
        COALESCE(
          SUM(
            CASE
              WHEN p.status = 'completed'
                AND p.payment_date >= ?
                AND p.payment_date < ?
              THEN p.amount
              ELSE 0
            END
          ),
          0
        ) AS paid_amount
      FROM commitments c
      LEFT JOIN payments p ON p.commitment_id = c.id
      WHERE c.user_id = ?
      GROUP BY c.id
      ORDER BY c.created_at DESC
    `,
    [cycle.startIso, cycle.endIso, auth.sub],
  );

  return c.json(commitments.map(serializeCommitment));
});

app.post('/commitments', async (c) => {
  const auth = c.get('auth');
  const body = validateCreateCommitment(await readJsonBody(c));
  const id = crypto.randomUUID();

  await dbRun(
    c.env.DB,
    `
      INSERT INTO commitments (
        id,
        user_id,
        title,
        description,
        amount,
        due_date,
        status,
        category
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      id,
      auth.sub,
      body.title,
      null,
      body.amount,
      null,
      'pending',
      body.category,
    ],
  );

  const commitment = await findCommitmentById(c.env.DB, auth.sub, id);
  return c.json(serializeCommitment(commitment), { status: 201 });
});

app.get('/commitments/:id', async (c) => {
  const auth = c.get('auth');
  const commitment = await findCommitmentById(c.env.DB, auth.sub, c.req.param('id'));
  return c.json(serializeCommitment(commitment));
});

app.put('/commitments/:id', async (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');
  await findCommitmentById(c.env.DB, auth.sub, id);

  const body = validateUpdateCommitment(await readJsonBody(c));
  const assignments: string[] = [];
  const values: Array<string | number | null> = [];

  for (const [key, value] of Object.entries(body)) {
    assignments.push(`${key} = ?`);
    values.push(value);
  }

  if (assignments.length > 0) {
    await dbRun(
      c.env.DB,
      `UPDATE commitments SET ${assignments.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?`,
      [...values, id, auth.sub],
    );
  }

  const commitment = await findCommitmentById(c.env.DB, auth.sub, id);
  return c.json(serializeCommitment(commitment));
});

app.delete('/commitments/:id', async (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');
  await findCommitmentById(c.env.DB, auth.sub, id);
  await dbRun(c.env.DB, 'DELETE FROM commitments WHERE id = ? AND user_id = ?', [id, auth.sub]);

  return c.json({
    message: 'Commitment deleted',
  });
});

app.get('/commitments/:id/payments', async (c) => {
  const auth = c.get('auth');
  const commitmentId = c.req.param('id');
  await findCommitmentById(c.env.DB, auth.sub, commitmentId);

  const payments = await dbAll<PaymentRow>(
    c.env.DB,
    'SELECT * FROM payments WHERE commitment_id = ? ORDER BY payment_date DESC, created_at DESC',
    [commitmentId],
  );

  return c.json(payments.map(serializePayment));
});

app.post('/commitments/:id/payments', async (c) => {
  const auth = c.get('auth');
  const commitmentId = c.req.param('id');
  const commitment = await findCommitmentById(c.env.DB, auth.sub, commitmentId);
  const body = validateRecordPayment(await readJsonBody(c));

  await ensurePaymentFitsCommitment(c.env.DB, commitment, body.amount);

  const id = crypto.randomUUID();
  await dbRun(
    c.env.DB,
    `
      INSERT INTO payments (
        id,
        commitment_id,
        amount,
        payment_date,
        method,
        status,
        reference,
        notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      id,
      commitmentId,
      body.amount,
      body.payment_date,
      body.method,
      body.status,
      body.reference,
      body.notes,
    ],
  );

  await syncCommitmentStatus(c.env.DB, commitmentId);
  const payment = await findPaymentById(c.env.DB, auth.sub, id);
  return c.json(serializePayment(payment), { status: 201 });
});

app.get('/payments/:id', async (c) => {
  const auth = c.get('auth');
  const payment = await findPaymentById(c.env.DB, auth.sub, c.req.param('id'));
  return c.json(serializePayment(payment));
});

app.put('/payments/:id', async (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');
  const payment = await findPaymentById(c.env.DB, auth.sub, id);
  const body = validateUpdatePayment(await readJsonBody(c));

  await dbRun(
    c.env.DB,
    'UPDATE payments SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [body.status, body.notes, id],
  );

  await syncCommitmentStatus(c.env.DB, payment.commitment_id);
  const updatedPayment = await findPaymentById(c.env.DB, auth.sub, id);
  return c.json(serializePayment(updatedPayment));
});

app.delete('/payments/:id', async (c) => {
  const auth = c.get('auth');
  const id = c.req.param('id');
  const payment = await findPaymentById(c.env.DB, auth.sub, id);

  await dbRun(c.env.DB, 'DELETE FROM payments WHERE id = ?', [id]);
  await syncCommitmentStatus(c.env.DB, payment.commitment_id);

  return c.json({
    message: 'Payment deleted',
  });
});

app.get('/api-json', (c) => c.json(buildOpenApiDocument(new URL(c.req.url).origin)));

app.get('/api-docs', (c) =>
  c.html(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>PayCycle API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui.css" />
    <style>
      body { margin: 0; background: #f8fafc; }
      #swagger-ui { max-width: 1200px; margin: 0 auto; }
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
    <script>
      window.onload = function () {
        SwaggerUIBundle({
          url: '/api-json',
          dom_id: '#swagger-ui',
          persistAuthorization: true
        });
      };
    </script>
  </body>
</html>`),
);

async function issueAuthTokens(secret: string, user: UserRow) {
  const now = getUnixTime();
  const accessToken = await sign(
    {
      sub: user.id,
      email: user.email,
      type: 'access',
      exp: now + 60 * 60,
    } satisfies JwtPayload,
    secret,
  );
  const refreshToken = await sign(
    {
      sub: user.id,
      email: user.email,
      type: 'refresh',
      exp: now + 60 * 60 * 24 * 30,
    } satisfies JwtPayload,
    secret,
  );

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: 'Bearer',
    expires_in: 3600,
  };
}

async function verifyJwt<T extends { exp?: number }>(token: string, secret: string): Promise<T> {
  let payload: T;

  try {
    payload = (await verify(token, secret, 'HS256')) as T;
  } catch {
    throw new ApiError(401, 'Invalid token');
  }

  if (typeof payload.exp === 'number' && payload.exp < getUnixTime()) {
    throw new ApiError(401, 'Token expired');
  }

  return payload;
}

function getUnixTime() {
  return Math.floor(Date.now() / 1000);
}

function getCurrentMonthlyCycle(now = new Date()) {
  const start = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0, 0),
  );
  const end = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0, 0),
  );

  return {
    start,
    end,
    startIso: start.toISOString(),
    endIso: end.toISOString(),
  };
}

function ensureGoogleConfig(env: Bindings) {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
    throw new ApiError(500, 'Google OAuth is not configured');
  }
}

const allowedAppRedirectUris = new Set(['paycycle://auth/callback']);

/**
 * The web app's redirect URI is dynamic (uses window.location.origin).
 * Accept any HTTPS URL ending with /auth/callback from allowed origins.
 */
function normalizeAppRedirectUri(value: string | undefined) {
  if (!value) {
    return null;
  }

  // Direct match for known app URIs
  if (allowedAppRedirectUris.has(value)) {
    return value;
  }

  // Accept HTTPS URLs ending with /auth/callback
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol === 'https:' &&
      parsed.pathname.endsWith('/auth/callback')
    ) {
      return value;
    }
  } catch {
    // not a valid URL, fall through to error
  }

  throw new ApiError(400, 'Unsupported app redirect URI');
}

function getGoogleRedirectUri(c: AppContext) {
  return c.env.GOOGLE_REDIRECT_URI || new URL('/auth/google/callback', c.req.url).toString();
}

function buildAppAuthSuccessRedirect(
  redirectTo: string,
  tokens: Awaited<ReturnType<typeof issueAuthTokens>>,
  user: ReturnType<typeof serializeUser>,
) {
  const url = new URL(redirectTo);
  url.searchParams.set('access_token', tokens.access_token);
  url.searchParams.set('refresh_token', tokens.refresh_token);
  url.searchParams.set('token_type', tokens.token_type);
  url.searchParams.set('expires_in', String(tokens.expires_in));
  url.searchParams.set('user_id', user.id);
  url.searchParams.set('user_email', user.email);
  url.searchParams.set('user_name', user.name);

  if (user.avatar_url) {
    url.searchParams.set('user_avatar_url', user.avatar_url);
  }
  if (user.created_at) {
    url.searchParams.set('user_created_at', user.created_at);
  }
  if (user.updated_at) {
    url.searchParams.set('user_updated_at', user.updated_at);
  }

  return url.toString();
}

function buildAppAuthErrorRedirect(redirectTo: string, message: string) {
  const url = new URL(redirectTo);
  url.searchParams.set('error', 'oauth_failed');
  url.searchParams.set('error_description', message);
  return url.toString();
}

function getPublicErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    return error.message;
  }

  if (error instanceof Error && error.message) {
    return error.message;
  }

  return 'Google sign-in failed';
}

async function exchangeGoogleCode(env: Bindings, code: string, redirectUri: string) {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  });

  if (!response.ok) {
    const details = await response.text();
    throw new ApiError(401, 'Failed to exchange Google authorization code', details);
  }

  return (await response.json()) as GoogleTokenResponse;
}

async function fetchGoogleUser(accessToken: string) {
  const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const details = await response.text();
    throw new ApiError(401, 'Failed to fetch Google user profile', details);
  }

  return (await response.json()) as GoogleUserInfo;
}

async function upsertGoogleUser(db: D1Database, profile: GoogleUserInfo) {
  const existing = await dbFirst<UserRow>(db, 'SELECT * FROM users WHERE google_id = ?', [profile.id]);

  if (existing) {
    await dbRun(
      db,
      'UPDATE users SET email = ?, name = ?, avatar_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [profile.email, profile.name, profile.picture ?? null, existing.id],
    );

    const updated = await dbFirst<UserRow>(db, 'SELECT * FROM users WHERE id = ?', [existing.id]);
    if (!updated) {
      throw new ApiError(500, 'Failed to reload updated user');
    }

    return updated;
  }

  const id = crypto.randomUUID();
  await dbRun(
    db,
    'INSERT INTO users (id, email, name, google_id, avatar_url) VALUES (?, ?, ?, ?, ?)',
    [id, profile.email, profile.name, profile.id, profile.picture ?? null],
  );

  const created = await dbFirst<UserRow>(db, 'SELECT * FROM users WHERE id = ?', [id]);
  if (!created) {
    throw new ApiError(500, 'Failed to load created user');
  }

  return created;
}

async function findCommitmentById(db: D1Database, userId: string, id: string) {
  const cycle = getCurrentMonthlyCycle();
  const commitment = await dbFirst<CommitmentRow>(
    db,
    `
      SELECT
        c.*,
        COALESCE(
          SUM(
            CASE
              WHEN p.status = 'completed'
                AND p.payment_date >= ?
                AND p.payment_date < ?
              THEN p.amount
              ELSE 0
            END
          ),
          0
        ) AS paid_amount
      FROM commitments c
      LEFT JOIN payments p ON p.commitment_id = c.id
      WHERE c.id = ? AND c.user_id = ?
      GROUP BY c.id
    `,
    [cycle.startIso, cycle.endIso, id, userId],
  );

  if (!commitment) {
    throw new ApiError(404, 'Commitment not found');
  }

  return commitment;
}

async function findPaymentById(db: D1Database, userId: string, id: string) {
  const payment = await dbFirst<PaymentRow>(
    db,
    `
      SELECT p.*
      FROM payments p
      INNER JOIN commitments c ON c.id = p.commitment_id
      WHERE p.id = ? AND c.user_id = ?
    `,
    [id, userId],
  );

  if (!payment) {
    throw new ApiError(404, 'Payment not found');
  }

  return payment;
}

async function ensurePaymentFitsCommitment(db: D1Database, commitment: CommitmentRow, nextAmount: number) {
  const cycle = getCurrentMonthlyCycle();
  const total = await dbFirst<{ total_paid: number | string | null }>(
    db,
    `
      SELECT COALESCE(SUM(amount), 0) AS total_paid
      FROM payments
      WHERE commitment_id = ? AND status IN ('pending', 'completed')
        AND payment_date >= ?
        AND payment_date < ?
    `,
    [commitment.id, cycle.startIso, cycle.endIso],
  );

  const commitmentAmount = toNumber(commitment.amount);
  const scheduledAmount = toNumber(total?.total_paid ?? 0);

  if (scheduledAmount + nextAmount > commitmentAmount) {
    throw new ApiError(400, 'Payment total exceeds commitment amount');
  }
}

async function syncCommitmentStatus(db: D1Database, commitmentId: string) {
  const commitment = await dbFirst<CommitmentRow>(
    db,
    'SELECT * FROM commitments WHERE id = ?',
    [commitmentId],
  );

  if (!commitment || commitment.status === 'cancelled') {
    return;
  }

  const cycle = getCurrentMonthlyCycle();
  const total = await dbFirst<{ paid_amount: number | string | null }>(
    db,
    `
      SELECT COALESCE(SUM(amount), 0) AS paid_amount
      FROM payments
      WHERE commitment_id = ?
        AND status = ?
        AND payment_date >= ?
        AND payment_date < ?
    `,
    [commitmentId, 'completed', cycle.startIso, cycle.endIso],
  );

  const nextStatus = getRecurringCommitmentStatus(
    {
      ...commitment,
      paid_amount: total?.paid_amount ?? 0,
    },
    cycle,
  );

  await dbRun(
    db,
    'UPDATE commitments SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [nextStatus, commitmentId],
  );
}

async function readJsonBody(c: AppContext): Promise<Record<string, unknown>> {
  try {
    return await c.req.json<Record<string, unknown>>();
  } catch {
    throw new ApiError(400, 'Invalid JSON body');
  }
}

function validateCreateCommitment(body: Record<string, unknown>) {
  return {
    title: requireString(body.title, 'title'),
    amount: requirePositiveNumber(body.amount, 'amount'),
    category: optionalString(body.category, 'category'),
  };
}

function validateUpdateCommitment(body: Record<string, unknown>) {
  const next: Record<string, string | number | null> = {};

  if (Object.prototype.hasOwnProperty.call(body, 'title')) {
    next.title = requireString(body.title, 'title');
  }
  if (Object.prototype.hasOwnProperty.call(body, 'amount')) {
    next.amount = requirePositiveNumber(body.amount, 'amount');
  }
  if (Object.prototype.hasOwnProperty.call(body, 'category')) {
    next.category = optionalString(body.category, 'category');
  }
  if (Object.prototype.hasOwnProperty.call(body, 'status')) {
    next.status = requireEnum(body.status, 'status', commitmentStatuses);
  }

  return next;
}

function validateRecordPayment(body: Record<string, unknown>) {
  return {
    amount: requirePositiveNumber(body.amount, 'amount'),
    payment_date: requireDate(body.payment_date, 'payment_date'),
    method: requireEnum(body.method, 'method', paymentMethods),
    status: body.status ? requireEnum(body.status, 'status', paymentStatuses) : 'completed',
    reference: optionalString(body.reference, 'reference'),
    notes: optionalString(body.notes, 'notes'),
  };
}

function validateUpdatePayment(body: Record<string, unknown>) {
  return {
    status: requireEnum(body.status, 'status', paymentStatuses),
    notes: optionalString(body.notes, 'notes'),
  };
}

function requireString(value: unknown, field: string) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ApiError(400, `Field "${field}" must be a non-empty string`);
  }

  return value.trim();
}

function optionalString(value: unknown, field: string) {
  if (value === undefined || value === null || value === '') {
    return null;
  }
  if (typeof value !== 'string') {
    throw new ApiError(400, `Field "${field}" must be a string`);
  }

  return value.trim();
}

function requirePositiveNumber(value: unknown, field: string) {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new ApiError(400, `Field "${field}" must be a positive number`);
  }

  return Number(parsed.toFixed(2));
}

function requireDate(value: unknown, field: string) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw new ApiError(400, `Field "${field}" must be an ISO 8601 date string`);
  }

  return value;
}

function requireEnum<T extends string>(value: unknown, field: string, allowed: T[]) {
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    throw new ApiError(400, `Field "${field}" must be one of: ${allowed.join(', ')}`);
  }

  return value as T;
}

function toNumber(value: string | number | null | undefined) {
  return Number(value ?? 0);
}

function serializeUser(user: UserRow) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    avatar_url: user.avatar_url,
    created_at: user.created_at,
    updated_at: user.updated_at,
  };
}

function serializeCommitment(commitment: CommitmentRow) {
  const cycle = getCurrentMonthlyCycle();
  return {
    id: commitment.id,
    user_id: commitment.user_id,
    title: commitment.title,
    due_date: cycle.startIso,
    status: getRecurringCommitmentStatus(commitment, cycle),
    amount: toNumber(commitment.amount),
    paid_amount: toNumber(commitment.paid_amount ?? 0),
    category: commitment.category,
    created_at: commitment.created_at,
    updated_at: commitment.updated_at,
  };
}

function getRecurringCommitmentStatus(
  commitment: CommitmentRow,
  cycle = getCurrentMonthlyCycle(),
): CommitmentStatus {
  if (commitment.status === 'cancelled') {
    return 'cancelled';
  }

  if (toNumber(commitment.paid_amount ?? 0) >= toNumber(commitment.amount)) {
    return 'completed';
  }

  return new Date().getTime() > cycle.start.getTime() ? 'overdue' : 'pending';
}

function serializePayment(payment: PaymentRow) {
  return {
    ...payment,
    amount: toNumber(payment.amount),
  };
}

async function dbAll<T>(db: D1Database, sql: string, params: unknown[] = []) {
  const result = await db.prepare(sql).bind(...params).all<T>();
  return result.results ?? [];
}

async function dbFirst<T>(db: D1Database, sql: string, params: unknown[] = []) {
  const result = await db.prepare(sql).bind(...params).first<T>();
  return result ?? null;
}

async function dbRun(db: D1Database, sql: string, params: unknown[] = []) {
  const result = await db.prepare(sql).bind(...params).run();
  if (!result.success) {
    throw new ApiError(500, 'Database query failed', result);
  }

  return result;
}

function buildOpenApiDocument(origin: string) {
  const unauthorizedResponse = {
    description: 'Missing, invalid, or expired bearer token',
    content: {
      'application/json': {
        schema: { $ref: '#/components/schemas/ErrorResponse' },
        examples: {
          invalidToken: {
            value: {
              error: {
                message: 'Invalid token',
              },
            },
          },
        },
      },
    },
  };

  const badRequestResponse = {
    description: 'Request validation failed',
    content: {
      'application/json': {
        schema: { $ref: '#/components/schemas/ErrorResponse' },
        examples: {
          validationError: {
            value: {
              error: {
                message: 'Field "amount" must be a positive number',
              },
            },
          },
        },
      },
    },
  };

  const notFoundResponse = {
    description: 'Requested resource was not found',
    content: {
      'application/json': {
        schema: { $ref: '#/components/schemas/ErrorResponse' },
        examples: {
          missingResource: {
            value: {
              error: {
                message: 'Commitment not found',
              },
            },
          },
        },
      },
    },
  };

  return {
    openapi: '3.0.3',
    info: {
      title: 'PayCycle API',
      version: '1.0.0',
      description:
        'Cloudflare Workers API for Google OAuth login, commitment CRUD, and commitment payment tracking backed by Cloudflare D1.',
      contact: {
        name: 'PayCycle API',
      },
    },
    servers: [{ url: origin }],
    externalDocs: {
      description: 'Swagger UI',
      url: `${origin}/api-docs`,
    },
    tags: [
      {
        name: 'Auth',
        description: 'Google OAuth login and token lifecycle endpoints.',
      },
      {
        name: 'Commitments',
        description: 'Create, read, update, and delete user commitments.',
      },
      {
        name: 'Payments',
        description: 'Manage payments attached to a commitment.',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            email: { type: 'string', format: 'email' },
            name: { type: 'string' },
            avatar_url: { type: 'string', nullable: true },
            created_at: { type: 'string', format: 'date-time' },
            updated_at: { type: 'string', format: 'date-time' },
          },
        },
        AuthResponse: {
          type: 'object',
          properties: {
            access_token: { type: 'string' },
            refresh_token: { type: 'string' },
            token_type: { type: 'string', example: 'Bearer' },
            expires_in: { type: 'integer', example: 3600 },
            user: { $ref: '#/components/schemas/User' },
          },
          example: {
            access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.access',
            refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh',
            token_type: 'Bearer',
            expires_in: 3600,
            user: {
              id: 'c7f87d73-c3d4-4f7c-8160-e526f6d90d49',
              email: 'user@example.com',
              name: 'John Doe',
              avatar_url: 'https://lh3.googleusercontent.com/a/example',
              created_at: '2026-05-03T00:00:00.000Z',
              updated_at: '2026-05-03T00:00:00.000Z',
            },
          },
        },
        Commitment: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            user_id: { type: 'string', format: 'uuid' },
            title: { type: 'string' },
            amount: { type: 'number', format: 'float' },
            paid_amount: { type: 'number', format: 'float' },
            due_date: { type: 'string', format: 'date-time', nullable: true },
            status: { type: 'string', enum: commitmentStatuses },
            category: { type: 'string', nullable: true },
            created_at: { type: 'string', format: 'date-time' },
            updated_at: { type: 'string', format: 'date-time' },
          },
          example: {
            id: 'cebc2d24-b4d6-4f20-bf3b-fc80892996d1',
            user_id: 'c7f87d73-c3d4-4f7c-8160-e526f6d90d49',
            title: 'Laptop Installment',
            amount: 3500,
            paid_amount: 1000,
            due_date: '2026-12-31T00:00:00.000Z',
            status: 'pending',
            category: 'electronics',
            created_at: '2026-05-03T00:00:00.000Z',
            updated_at: '2026-05-03T00:00:00.000Z',
          },
        },
        Payment: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            commitment_id: { type: 'string', format: 'uuid' },
            amount: { type: 'number', format: 'float' },
            payment_date: { type: 'string', format: 'date-time' },
            method: { type: 'string', enum: paymentMethods },
            status: { type: 'string', enum: paymentStatuses },
            reference: { type: 'string', nullable: true },
            notes: { type: 'string', nullable: true },
            created_at: { type: 'string', format: 'date-time' },
            updated_at: { type: 'string', format: 'date-time' },
          },
          example: {
            id: '63598392-1445-4155-8615-e17af552c787',
            commitment_id: 'cebc2d24-b4d6-4f20-bf3b-fc80892996d1',
            amount: 500,
            payment_date: '2026-05-10T09:00:00.000Z',
            method: 'bank_transfer',
            status: 'completed',
            reference: 'INV-2026-001',
            notes: 'First installment paid',
            created_at: '2026-05-10T09:01:00.000Z',
            updated_at: '2026-05-10T09:01:00.000Z',
          },
        },
        CreateCommitmentRequest: {
          type: 'object',
          required: ['title', 'amount'],
          properties: {
            title: { type: 'string' },
            amount: { type: 'number', format: 'float' },
            due_date: { type: 'string', format: 'date-time' },
            category: { type: 'string' },
          },
          example: {
            title: 'Laptop Installment',
            amount: 3500,
            due_date: '2026-12-31T00:00:00.000Z',
            category: 'electronics',
          },
        },
        UpdateCommitmentRequest: {
          type: 'object',
          properties: {
            title: { type: 'string' },
            amount: { type: 'number', format: 'float' },
            due_date: { type: 'string', format: 'date-time', nullable: true },
            status: { type: 'string', enum: commitmentStatuses },
            category: { type: 'string', nullable: true },
          },
          example: {
            status: 'completed',
            category: 'electronics',
          },
        },
        RecordPaymentRequest: {
          type: 'object',
          required: ['amount', 'payment_date', 'method'],
          properties: {
            amount: { type: 'number', format: 'float' },
            payment_date: { type: 'string', format: 'date-time' },
            method: { type: 'string', enum: paymentMethods },
            status: { type: 'string', enum: paymentStatuses, default: 'completed' },
            reference: { type: 'string' },
            notes: { type: 'string' },
          },
          example: {
            amount: 500,
            payment_date: '2026-05-10T09:00:00.000Z',
            method: 'bank_transfer',
            status: 'completed',
            reference: 'INV-2026-001',
            notes: 'First installment paid',
          },
        },
        UpdatePaymentRequest: {
          type: 'object',
          required: ['status'],
          properties: {
            status: { type: 'string', enum: paymentStatuses },
            notes: { type: 'string', nullable: true },
          },
          example: {
            status: 'refunded',
            notes: 'Refund processed by merchant',
          },
        },
        RefreshTokenRequest: {
          type: 'object',
          required: ['refresh_token'],
          properties: {
            refresh_token: { type: 'string' },
          },
          example: {
            refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh',
          },
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            error: {
              type: 'object',
              properties: {
                message: { type: 'string' },
              },
            },
          },
        },
      },
    },
    paths: {
      '/': {
        get: {
          tags: ['Auth'],
          summary: 'Get API metadata',
          description: 'Returns the API name, version, and documentation URLs.',
          responses: {
            '200': {
              description: 'API metadata',
            },
          },
        },
      },
      '/health': {
        get: {
          tags: ['Auth'],
          summary: 'Health check',
          description: 'Simple readiness check for the Cloudflare Worker.',
          responses: {
            '200': {
              description: 'Worker is healthy',
            },
          },
        },
      },
      '/auth/google': {
        get: {
          tags: ['Auth'],
          summary: 'Redirect to Google OAuth',
          description: 'Starts the Google OAuth login flow and redirects the client to the Google consent screen.',
          responses: {
            '302': { description: 'Redirects to Google consent screen' },
            '500': {
              description: 'Google OAuth is not configured',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ErrorResponse' },
                },
              },
            },
          },
        },
      },
      '/auth/google/callback': {
        get: {
          tags: ['Auth'],
          summary: 'Handle Google OAuth callback',
          description: 'Completes the Google OAuth flow, creates or updates the user, and returns API JWTs.',
          parameters: [
            {
              in: 'query',
              name: 'code',
              required: true,
              schema: { type: 'string' },
            },
            {
              in: 'query',
              name: 'state',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Returns API tokens for the authenticated user',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthResponse' },
                },
              },
            },
            '400': badRequestResponse,
            '401': unauthorizedResponse,
            '403': {
              description: 'Google account email is not verified',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ErrorResponse' },
                },
              },
            },
          },
        },
      },
      '/auth/refresh': {
        post: {
          tags: ['Auth'],
          summary: 'Refresh access token',
          description: 'Exchanges a valid refresh token for a fresh access token and refresh token pair.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RefreshTokenRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'Returns new access and refresh tokens',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthResponse' },
                },
              },
            },
            '400': badRequestResponse,
            '401': unauthorizedResponse,
          },
        },
      },
      '/auth/logout': {
        post: {
          tags: ['Auth'],
          summary: 'Logout current client session',
          description: 'Stateless logout endpoint. The client should delete its stored access and refresh tokens.',
          responses: {
            '200': {
              description: 'Logout acknowledgement',
            },
          },
        },
      },
      '/commitments': {
        get: {
          tags: ['Commitments'],
          summary: 'List commitments for the authenticated user',
          description: 'Returns all commitments owned by the authenticated user, newest first.',
          security: [{ bearerAuth: [] }],
          responses: {
            '200': {
              description: 'Commitment list',
              content: {
                'application/json': {
                  schema: {
                    type: 'array',
                    items: { $ref: '#/components/schemas/Commitment' },
                  },
                },
              },
            },
            '401': unauthorizedResponse,
          },
        },
        post: {
          tags: ['Commitments'],
          summary: 'Create a new commitment',
          description: 'Creates a commitment for the authenticated user in Cloudflare D1.',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CreateCommitmentRequest' },
              },
            },
          },
          responses: {
            '201': {
              description: 'Created commitment',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Commitment' },
                },
              },
            },
            '400': badRequestResponse,
            '401': unauthorizedResponse,
          },
        },
      },
      '/commitments/{id}': {
        get: {
          tags: ['Commitments'],
          summary: 'Get a commitment by id',
          description: 'Returns one commitment owned by the authenticated user.',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Commitment detail',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Commitment' },
                },
              },
            },
            '401': unauthorizedResponse,
            '404': notFoundResponse,
          },
        },
        put: {
          tags: ['Commitments'],
          summary: 'Update a commitment',
          description: 'Updates one or more commitment fields for the authenticated user.',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: { type: 'string' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UpdateCommitmentRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'Updated commitment',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Commitment' },
                },
              },
            },
            '400': badRequestResponse,
            '401': unauthorizedResponse,
            '404': notFoundResponse,
          },
        },
        delete: {
          tags: ['Commitments'],
          summary: 'Delete a commitment',
          description: 'Deletes a commitment and its related payments.',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Delete confirmation',
            },
            '401': unauthorizedResponse,
            '404': notFoundResponse,
          },
        },
      },
      '/commitments/{id}/payments': {
        get: {
          tags: ['Payments'],
          summary: 'List payments for a commitment',
          description: 'Returns all payments recorded for one commitment owned by the authenticated user.',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Payment list',
              content: {
                'application/json': {
                  schema: {
                    type: 'array',
                    items: { $ref: '#/components/schemas/Payment' },
                  },
                },
              },
            },
            '401': unauthorizedResponse,
            '404': notFoundResponse,
          },
        },
        post: {
          tags: ['Payments'],
          summary: 'Record a payment for a commitment',
          description: 'Creates a payment record and updates the related commitment status if needed.',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: { type: 'string' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RecordPaymentRequest' },
              },
            },
          },
          responses: {
            '201': {
              description: 'Created payment',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Payment' },
                },
              },
            },
            '400': badRequestResponse,
            '401': unauthorizedResponse,
            '404': notFoundResponse,
          },
        },
      },
      '/payments/{id}': {
        get: {
          tags: ['Payments'],
          summary: 'Get a payment by id',
          description: 'Returns one payment owned by the authenticated user through its parent commitment.',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Payment detail',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Payment' },
                },
              },
            },
            '401': unauthorizedResponse,
            '404': {
              description: 'Payment not found',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ErrorResponse' },
                },
              },
            },
          },
        },
        put: {
          tags: ['Payments'],
          summary: 'Update payment status',
          description: 'Updates the payment status and notes, then synchronizes the related commitment status.',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: { type: 'string' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UpdatePaymentRequest' },
              },
            },
          },
          responses: {
            '200': {
              description: 'Updated payment',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Payment' },
                },
              },
            },
            '400': badRequestResponse,
            '401': unauthorizedResponse,
            '404': {
              description: 'Payment not found',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ErrorResponse' },
                },
              },
            },
          },
        },
        delete: {
          tags: ['Payments'],
          summary: 'Delete a payment',
          description: 'Deletes a payment and recalculates the parent commitment status.',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': {
              description: 'Delete confirmation',
            },
            '401': unauthorizedResponse,
            '404': {
              description: 'Payment not found',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ErrorResponse' },
                },
              },
            },
          },
        },
      },
    },
  };
}

export default app;
