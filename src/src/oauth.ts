// OAuth 2.1 authorization-server layer for Claude custom connectors.
//
// Claude's current connector flow requires the MCP endpoint to be protected by
// an OAuth 2.1 (PKCE) flow with discovery metadata and Dynamic Client
// Registration. This module implements exactly that, as a thin gate in front of
// /mcp. It is intentionally DECOUPLED from Whoop auth: completing this flow only
// proves "Claude is allowed to talk to this server." The actual Whoop login is
// still handled separately by the in-chat `get_auth_url` tool.
//
// Storage is in-memory. On a process restart these are cleared and Claude will
// transparently re-run the (one-click) OAuth flow. That is fine for personal use.

import crypto from 'node:crypto';
import type { Express, Request, Response, NextFunction } from 'express';

interface RegisteredClient {
	client_id: string;
	client_secret?: string;
	redirect_uris: string[];
}

interface AuthCode {
	client_id: string;
	redirect_uri: string;
	code_challenge: string;
	expires_at: number;
}

interface AccessToken {
	expires_at: number;
}

const clients = new Map<string, RegisteredClient>();
const authCodes = new Map<string, AuthCode>();
const accessTokens = new Map<string, AccessToken>();
const refreshTokens = new Set<string>();

const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour
const AUTH_CODE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function randomToken(): string {
	return crypto.randomBytes(32).toString('base64url');
}

function base64UrlSha256(input: string): string {
	return crypto.createHash('sha256').update(input).digest('base64url');
}

// Derive the server's public base URL. Render (and most PaaS) set the
// x-forwarded-* headers. PUBLIC_URL overrides if you want to pin it.
function baseUrl(req: Request): string {
	if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/$/, '');
	const proto = (req.headers['x-forwarded-proto'] as string | undefined)?.split(',')[0] ?? req.protocol;
	const host = (req.headers['x-forwarded-host'] as string | undefined) ?? req.headers.host;
	return `${proto}://${host}`;
}

function isValidAccessToken(token: string | undefined): boolean {
	if (!token) return false;
	const entry = accessTokens.get(token);
	if (!entry) return false;
	if (Date.now() > entry.expires_at) {
		accessTokens.delete(token);
		return false;
	}
	return true;
}

// Express middleware to protect /mcp. On missing/invalid bearer token, returns
// 401 with a WWW-Authenticate header pointing Claude at the resource metadata.
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
	const header = req.headers.authorization ?? '';
	const token = header.startsWith('Bearer ') ? header.slice(7) : undefined;
	if (isValidAccessToken(token)) {
		next();
		return;
	}
	const metadataUrl = `${baseUrl(req)}/.well-known/oauth-protected-resource`;
	res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${metadataUrl}"`);
	res.status(401).json({ error: 'invalid_token', error_description: 'Authentication required' });
}

export function mountOAuth(app: Express): void {
	// --- Discovery: Protected Resource Metadata (RFC 9728) ---
	const protectedResource = (req: Request, res: Response): void => {
		const base = baseUrl(req);
		res.json({
			resource: `${base}/mcp`,
			authorization_servers: [base],
		});
	};
	app.get('/.well-known/oauth-protected-resource', protectedResource);
	app.get('/.well-known/oauth-protected-resource/mcp', protectedResource);

	// --- Discovery: Authorization Server Metadata (RFC 8414) ---
	app.get('/.well-known/oauth-authorization-server', (req: Request, res: Response) => {
		const base = baseUrl(req);
		res.json({
			issuer: base,
			authorization_endpoint: `${base}/authorize`,
			token_endpoint: `${base}/token`,
			registration_endpoint: `${base}/register`,
			response_types_supported: ['code'],
			grant_types_supported: ['authorization_code', 'refresh_token'],
			code_challenge_methods_supported: ['S256'],
			token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
			scopes_supported: ['whoop'],
		});
	});

	// --- Dynamic Client Registration (RFC 7591) ---
	app.post('/register', (req: Request, res: Response) => {
		const body = (req.body ?? {}) as { redirect_uris?: unknown };
		const redirectUris = Array.isArray(body.redirect_uris)
			? body.redirect_uris.filter((u): u is string => typeof u === 'string')
			: [];
		if (redirectUris.length === 0) {
			res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris required' });
			return;
		}
		const client: RegisteredClient = {
			client_id: `client_${randomToken()}`,
			redirect_uris: redirectUris,
		};
		clients.set(client.client_id, client);
		res.status(201).json({
			client_id: client.client_id,
			redirect_uris: client.redirect_uris,
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
		});
	});

	// --- Authorization endpoint: interactive consent, then redirect with code ---
	app.get('/authorize', (req: Request, res: Response) => {
		const { client_id, redirect_uri, response_type, code_challenge, code_challenge_method, state } =
			req.query as Record<string, string | undefined>;

		const client = client_id ? clients.get(client_id) : undefined;
		if (!client_id || !client) {
			res.status(400).send('Unknown client_id. Re-add the connector in Claude.');
			return;
		}
		if (!redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
			res.status(400).send('redirect_uri not registered for this client.');
			return;
		}
		if (response_type !== 'code') {
			res.status(400).send('Unsupported response_type (expected "code").');
			return;
		}
		if (!code_challenge || code_challenge_method !== 'S256') {
			res.status(400).send('PKCE with S256 is required.');
			return;
		}

		// Render a minimal interactive consent page. Approving GETs /authorize/approve
		// with the same parameters, which then issues the code and redirects back.
		const q = new URLSearchParams({
			client_id,
			redirect_uri,
			code_challenge,
			state: state ?? '',
		}).toString();
		res.setHeader('Content-Type', 'text/html');
		res.send(`<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize Claude</title>
<style>body{font-family:system-ui,sans-serif;max-width:420px;margin:80px auto;padding:0 20px;text-align:center;color:#222}
h1{font-size:20px}button{font-size:16px;padding:12px 28px;border:0;border-radius:8px;background:#111;color:#fff;cursor:pointer}
p{color:#555;line-height:1.5}</style></head>
<body><h1>Connect Claude to your Whoop MCP server</h1>
<p>Claude is requesting access to this server. After you approve, you'll still need to authorize Whoop itself once inside Claude (ask it to "connect to my Whoop data").</p>
<a href="/authorize/approve?${q}"><button>Approve</button></a></body></html>`);
	});

	app.get('/authorize/approve', (req: Request, res: Response) => {
		const { client_id, redirect_uri, code_challenge, state } = req.query as Record<string, string | undefined>;
		const client = client_id ? clients.get(client_id) : undefined;
		if (!client_id || !client || !redirect_uri || !client.redirect_uris.includes(redirect_uri) || !code_challenge) {
			res.status(400).send('Invalid authorization request.');
			return;
		}
		const code = randomToken();
		authCodes.set(code, {
			client_id,
			redirect_uri,
			code_challenge,
			expires_at: Date.now() + AUTH_CODE_TTL_MS,
		});
		const url = new URL(redirect_uri);
		url.searchParams.set('code', code);
		if (state) url.searchParams.set('state', state);
		res.redirect(url.toString());
	});

	// --- Token endpoint: authorization_code (with PKCE) and refresh_token ---
	app.post('/token', (req: Request, res: Response) => {
		const body = (req.body ?? {}) as Record<string, string | undefined>;
		const grantType = body.grant_type;

		if (grantType === 'authorization_code') {
			const { code, code_verifier, redirect_uri, client_id } = body;
			const entry = code ? authCodes.get(code) : undefined;
			if (!entry || Date.now() > entry.expires_at) {
				if (code) authCodes.delete(code);
				res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired code' });
				return;
			}
			authCodes.delete(code!); // single use
			if (entry.client_id !== client_id || entry.redirect_uri !== redirect_uri) {
				res.status(400).json({ error: 'invalid_grant', error_description: 'Client/redirect mismatch' });
				return;
			}
			if (!code_verifier || base64UrlSha256(code_verifier) !== entry.code_challenge) {
				res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
				return;
			}
			issueTokens(res);
			return;
		}

		if (grantType === 'refresh_token') {
			const { refresh_token } = body;
			if (!refresh_token || !refreshTokens.has(refresh_token)) {
				res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid refresh token' });
				return;
			}
			refreshTokens.delete(refresh_token); // rotate
			issueTokens(res);
			return;
		}

		res.status(400).json({ error: 'unsupported_grant_type' });
	});
}

function issueTokens(res: Response): void {
	const accessToken = randomToken();
	const refreshToken = randomToken();
	accessTokens.set(accessToken, { expires_at: Date.now() + ACCESS_TOKEN_TTL_MS });
	refreshTokens.add(refreshToken);
	res.json({
		access_token: accessToken,
		token_type: 'Bearer',
		expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
		refresh_token: refreshToken,
		scope: 'whoop',
	});
}
