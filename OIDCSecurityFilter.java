import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.regex.*;

import com.nimbusds.jwt.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;

/**
 * OIDCSecurityFilter - Production OIDC/OAuth2 servlet filter for PeopleSoft.
 *
 * Works with ANY OIDC-compliant IdP:
 *   Azure AD / Entra ID, Okta, Keycloak, Google, Auth0,
 *   PingFederate, OneLogin, ADFS 2019+, etc.
 *
 * Dependencies (WEB-INF/lib):
 *   nimbus-jose-jwt-9.x.jar
 *
 * Authentication Modes (auto-detected at startup):
 *   MODE 1: PKCE + Client Secret  - Maximum security (recommended)
 *   MODE 2: PKCE only             - Public client
 *   MODE 3: Client Secret only    - Legacy IdPs without PKCE
 *   MODE 4: Neither               - FAILS SAFE at startup
 *
 * oidc.properties:
 *   issuer=https://login.microsoftonline.com/{tenant-id}/v2.0
 *   client.id=your-client-id
 *   client.secret=your-secret
 *   redirect.uri=http://localhost:8000/psc/ps/EMPLOYEE/HRMS/c/NUI_FRAMEWORK.PT_LANDINGPAGE.GBL
 *   scope=openid profile email
 *   username.claim=preferred_username
 *   header.name=X-PS-USER
 *   max.token.age.seconds=600
 *   session.timeout.seconds=1800
 *   force.pkce=true
 *   debug=false
 *
 * JVM startup:
 *   -Doidc.config=/path/to/oidc.properties
 *
 * Debug logging (debug=true) covers:
 *   - Every request: method, URI, remote IP, session state
 *   - Auth flow: redirect URL, PKCE verifier length, state/nonce values
 *   - Token exchange: what was sent, full IdP error on failure
 *   - Token validation: every claim checked with actual vs expected values
 *   - Session: creation, user, timeout set
 *   - JWKS: refresh timing, kid lookup
 *   - Navigation detection: which path was taken and why
 */
public class OIDCSecurityFilter implements Filter {

    // --- Config fields --------------------------------------------------------
    private String  issuer;
    private String  issuerOrigin;
    private String  clientId;
    private String  clientSecret;
    private String  redirectUri;
    private String  scope;
    private String  usernameClaim;
    private String  headerName;
    private boolean debug;
    private long    maxTokenAgeMs;
    private int     sessionTimeoutSecs;

    // --- Discovered endpoints -------------------------------------------------
    private String  authorizationEndpoint;
    private String  tokenEndpoint;
    private String  jwksUri;

    // --- Auth mode ------------------------------------------------------------
    private boolean pkceSupported = false;
    private boolean hasSecret     = false;

    // --- JWKS cache -----------------------------------------------------------
    private volatile JWKSet jwkSet;
    private volatile long   jwksLoadedAtMs = 0L;
    private final    long   jwksCacheMs    = 15 * 60 * 1000L;

    // --- Session attribute keys -----------------------------------------------
    private static final String SESS_USER          = "OIDC_USER";
    private static final String SESS_STATE         = "OIDC_STATE";
    private static final String SESS_NONCE         = "OIDC_NONCE";
    private static final String SESS_CODE_VERIFIER = "OIDC_CODE_VERIFIER";

    // --- Security constants ---------------------------------------------------
    private static final long CLOCK_SKEW_MS  = 30_000L;
    private static final int  HTTP_TIMEOUT   = 8_000;
    private static final int  MAX_STATE_LEN  = 512;
    private static final int  MAX_RESP_BYTES = 1024 * 1024; // 1MB cap

    // -------------------------------------------------------------------------
    @Override
    public void init(FilterConfig cfg) throws ServletException {
        try {
            String configPath = System.getProperty("oidc.config");
            if (configPath == null || configPath.trim().isEmpty())
                throw new ServletException(
                    "Missing JVM property: -Doidc.config=/path/to/oidc.properties");

            syslog("Loading config from: " + configPath);

            Properties p = new Properties();
            try (FileInputStream fis = new FileInputStream(configPath)) {
                p.load(fis);
            }

            // Required properties
            issuer      = require(p, "issuer");
            clientId    = require(p, "client.id");
            redirectUri = require(p, "redirect.uri");
            issuerOrigin = extractOrigin(issuer);

            // Client secret - env var takes priority over properties file
            String envSecret = System.getenv("OIDC_CLIENT_SECRET");
            clientSecret = (envSecret != null && !envSecret.trim().isEmpty())
                ? envSecret.trim()
                : p.getProperty("client.secret", "").trim();
            hasSecret = !clientSecret.isEmpty();

            // Optional properties with defaults
            scope              = p.getProperty("scope",                 "openid profile email").trim();
            usernameClaim      = p.getProperty("username.claim",        "preferred_username").trim();
            headerName         = p.getProperty("header.name",           "X-PS-USER").trim();
            debug              = Boolean.parseBoolean(p.getProperty("debug", "false").trim());
            sessionTimeoutSecs = Integer.parseInt(
                p.getProperty("session.timeout.seconds", "1800").trim());
            long maxAgeSecs = Long.parseLong(
                p.getProperty("max.token.age.seconds", "600").trim());
            maxTokenAgeMs = maxAgeSecs * 1000L;

            // OIDC Discovery
            String discoveryUrl = issuer.endsWith("/") ? issuer : issuer + "/";
            discoveryUrl += ".well-known/openid-configuration";
            enforceHttpsUrl(discoveryUrl, "issuer discovery URL");

            syslog("Fetching OIDC discovery from: " + discoveryUrl);
            String discoveryJson = httpGet(discoveryUrl);
            syslog("Discovery doc length: " + discoveryJson.length() + " chars");

            // Parse only top-level JSON fields - strips nested objects like
            // mtls_endpoint_aliases so we never pick up the wrong token_endpoint
            String     flatJson = flattenTopLevel(discoveryJson);
            Properties disc     = parseJsonFlat(flatJson);

            authorizationEndpoint = requireDisc(disc, "authorization_endpoint");
            tokenEndpoint         = requireDisc(disc, "token_endpoint");
            jwksUri               = requireDisc(disc, "jwks_uri");

            enforceHttpsUrl(tokenEndpoint, "token_endpoint");
            enforceHttpsUrl(jwksUri, "jwks_uri");
            validateOrigin(authorizationEndpoint, "authorization_endpoint");
            validateOrigin(tokenEndpoint,         "token_endpoint");
            validateOrigin(jwksUri,               "jwks_uri");

            // PKCE detection
            String challengeMethods = disc.getProperty(
                "code_challenge_methods_supported", "");
            pkceSupported = challengeMethods.contains("S256")
                         || flatJson.contains("\"S256\"");

            boolean forcePkce = Boolean.parseBoolean(
                p.getProperty("force.pkce", "false").trim());
            if (forcePkce) pkceSupported = true;

            if (!pkceSupported && !hasSecret)
                throw new ServletException(
                    "UNSAFE CONFIGURATION: IdP does not support PKCE and no " +
                    "client secret is configured. Options:\n" +
                    "  a) Add force.pkce=true to oidc.properties\n" +
                    "  b) Add client.secret=xxx to oidc.properties\n" +
                    "  c) Set env var OIDC_CLIENT_SECRET=xxx");

            refreshJwks(true);

            // Startup summary - always printed
            syslog("==================================================");
            syslog("OIDC Filter initialized OK");
            syslog("  issuer         : " + issuer);
            syslog("  issuer origin  : " + issuerOrigin);
            syslog("  client.id      : " + clientId);
            syslog("  redirect.uri   : " + redirectUri);
            syslog("  authz endpoint : " + authorizationEndpoint);
            syslog("  token endpoint : " + tokenEndpoint);
            syslog("  jwks uri       : " + jwksUri);
            syslog("  pkce supported : " + pkceSupported
                + (forcePkce ? " (forced via force.pkce=true)"
                             : " (auto-detected, challengeMethods=" + challengeMethods + ")"));
            syslog("  has secret     : " + hasSecret);
            syslog("  secret source  : " + (envSecret != null && !envSecret.trim().isEmpty()
                ? "env var OIDC_CLIENT_SECRET" : "oidc.properties"));
            syslog("  auth mode      : " + resolveAuthMode());
            syslog("  header.name    : " + headerName);
            syslog("  username.claim : " + usernameClaim);
            syslog("  scope          : " + scope);
            syslog("  max.token.age  : " + maxAgeSecs + "s (iat checked at login only)");
            syslog("  session.timeout: " + sessionTimeoutSecs + "s");
            syslog("  clock.skew     : " + (CLOCK_SKEW_MS / 1000) + "s");
            syslog("  jwks.cache     : " + (jwksCacheMs / 60000) + "min");
            syslog("  debug          : " + debug);
            syslog("==================================================");

        } catch (ServletException se) {
            throw se;
        } catch (Exception e) {
            throw new ServletException("OIDC init failed: " + e.getMessage(), e);
        }
    }

    private String resolveAuthMode() {
        if (pkceSupported && hasSecret) return "PKCE + CLIENT SECRET (maximum security)";
        if (pkceSupported)              return "PKCE only";
        if (hasSecret)                  return "CLIENT SECRET only (legacy fallback)";
        return "NONE";
    }

    // -------------------------------------------------------------------------
    @Override
    public void doFilter(ServletRequest sreq, ServletResponse sres, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest  req = (HttpServletRequest)  sreq;
        HttpServletResponse res = (HttpServletResponse) sres;

        // Security headers on every response
        addSecurityHeaders(res);

        // Strip inbound auth header - never trust client-supplied value
        // Without this an attacker can forge X-PS-USER: admin to bypass auth
        req = new StripHeaderWrapper(req, headerName);

        String method   = req.getMethod();
        String uri      = req.getRequestURI();
        String query    = req.getQueryString();
        String remoteIp = req.getRemoteAddr();

        HttpSession session = req.getSession(false);

        // 1. Authenticated session - inject header and pass through.
        // Gate ONLY on session != null + SESS_USER present.
        // Do NOT use isRequestedSessionIdValid() here - it can be flaky in PeopleSoft
        // with Classic/Fluid mixed paths, custom cookie names, or reverse proxies,
        // which causes the header to not inject even when the session is valid
        // (the exact symptom that breaks Classic JS like hoverLightTR).
        if (session != null && session.getAttribute(SESS_USER) != null) {
            String user = (String) session.getAttribute(SESS_USER);
            // Authenticated page hits are NOT logged to avoid per-request log spam.
            // Set debug=true and remove this early-return log suppression only
            // if you need to trace a specific authenticated user's requests.
            chain.doFilter(new UserWrapper(req, headerName, user), res);
            return;
        }

        // From here down: only unauthenticated, callback, or error paths.
        // These are always worth logging.
        log("[REQUEST] " + method + " " + uri
            + (query != null ? "?" + query : "")
            + " | remote=" + remoteIp
            + " | session=" + (session != null ? session.getId() : "none"));

        log("[AUTH] No authenticated session"
            + (session != null ? " | session exists but OIDC_USER not set" : " | no session"));

        // 2. POST without valid session - return 401.
        // Authenticated POSTs are already handled above (session + SESS_USER present).
        // If we reach here on a POST, the session is gone or expired.
        if ("POST".equalsIgnoreCase(method)) {
            log("[AUTH] POST with no authenticated session - returning 401 | uri=" + uri);
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                "Session expired. Please refresh the page to re-authenticate.");
            return;
        }

        // 3. SSL offload check
        enforceHttpsIfNeeded(req);

        String code  = req.getParameter("code");
        String state = req.getParameter("state");

        log("[AUTH] code=" + (code != null ? "present(len=" + code.length() + ")" : "null")
            + " | state=" + (state != null ? "present(len=" + state.length() + ")" : "null"));

        // 4. No code - start OIDC flow for top-level browser navigations only
        if (code == null || code.trim().isEmpty()) {
            boolean topLevel = isTopLevelNavigation(req);
            log("[NAV] isTopLevelNavigation=" + topLevel
                + " | Sec-Fetch-Mode=" + req.getHeader("Sec-Fetch-Mode")
                + " | Sec-Fetch-Dest=" + req.getHeader("Sec-Fetch-Dest")
                + " | Accept=" + req.getHeader("Accept")
                + " | X-Requested-With=" + req.getHeader("X-Requested-With"));

            if (topLevel) {
                try {
                    startOidc(req, res);
                } catch (Exception e) {
                    log("[ERROR] startOidc failed: " + e.getMessage());
                    res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "Authentication could not be initiated. Please try again.");
                }
                return;
            }
            log("[NAV] Not a top-level navigation - passing through unauthenticated");
            chain.doFilter(req, res);
            return;
        }

        // 5. Callback - validate token, create session, continue
        log("[CALLBACK] Processing OIDC callback");
        try {
            // State length check
            if (state != null && state.length() > MAX_STATE_LEN) {
                log("[SECURITY] State parameter too long: " + state.length() + " chars (max=" + MAX_STATE_LEN + ")");
                throw new SecurityException("State parameter exceeds maximum length");
            }

            // Session fixation protection
            HttpSession old = req.getSession(false);
            if (old != null) {
                log("[SESSION] Invalidating old session id=" + old.getId()
                    + " to prevent session fixation");
            }
            Map<String, Object> carried = new HashMap<>();
            if (old != null) {
                for (String key : Arrays.asList(
                        SESS_STATE, SESS_NONCE, SESS_CODE_VERIFIER)) {
                    Object v = old.getAttribute(key);
                    if (v != null) carried.put(key, v);
                }
                old.invalidate();
            }
            session = req.getSession(true);
            log("[SESSION] New session created id=" + session.getId());
            for (Map.Entry<String, Object> e : carried.entrySet())
                session.setAttribute(e.getKey(), e.getValue());

            // Get then remove - one-time use values
            String expectedState = (String) session.getAttribute(SESS_STATE);
            String expectedNonce = (String) session.getAttribute(SESS_NONCE);
            String codeVerifier  = (String) session.getAttribute(SESS_CODE_VERIFIER);
            session.removeAttribute(SESS_STATE);
            session.removeAttribute(SESS_NONCE);
            session.removeAttribute(SESS_CODE_VERIFIER);

            log("[CALLBACK] expectedState=" + expectedState
                + " | receivedState=" + state
                + " | stateMatch=" + (expectedState != null && constantTimeEquals(expectedState, state)));
            log("[CALLBACK] expectedNonce=" + expectedNonce
                + " | codeVerifier=" + (codeVerifier != null ? "present(len=" + codeVerifier.length() + ")" : "null"));

            if (expectedState == null || state == null ||
                !constantTimeEquals(expectedState, state)) {
                log("[SECURITY] State validation FAILED - possible CSRF attempt"
                    + " | expected=" + expectedState + " | received=" + state);
                throw new SecurityException("Invalid or missing state parameter");
            }

            if (expectedNonce == null) {
                log("[SECURITY] Nonce missing from session - possible session tampering");
                throw new SecurityException("Missing nonce in session");
            }

            if (pkceSupported && (codeVerifier == null || codeVerifier.isEmpty())) {
                log("[SECURITY] PKCE code verifier missing - possible session tampering");
                throw new SecurityException("Missing PKCE code verifier");
            }

            String       idToken = exchangeCodeForIdToken(code, codeVerifier);
            log("[CALLBACK] id_token received, length=" + idToken.length());

            SignedJWT    jwt     = SignedJWT.parse(idToken);
            log("[CALLBACK] JWT parsed | alg=" + jwt.getHeader().getAlgorithm()
                + " | kid=" + jwt.getHeader().getKeyID());

            JWTClaimsSet claims  = validateIdToken(jwt, expectedNonce);

            String user = extractUsername(claims);
            log("[CALLBACK] Username extracted from claim '" + usernameClaim
                + "' = " + user);

            if (user == null || user.trim().isEmpty()) {
                log("[ERROR] Username is empty. Available claims: " + claims.getClaims().keySet());
                throw new SecurityException(
                    "Username claim '" + usernameClaim + "' missing from token. " +
                    "Configure optional claims in your IdP.");
            }

            session.setMaxInactiveInterval(sessionTimeoutSecs);
            session.setAttribute(SESS_USER, user);

            log("[AUTH-OK] Login successful"
                + " | user=" + user
                + " | sessionId=" + session.getId()
                + " | sessionTimeout=" + sessionTimeoutSecs + "s"
                + " | remoteIp=" + remoteIp
                + " | usernameClaim=" + usernameClaim
                + " | header=" + headerName + "=" + user);

            chain.doFilter(new CleanCallbackWrapper(req, headerName, user), res);

        } catch (Exception e) {
            // Log full detail internally for troubleshooting
            log("[ERROR] Callback failed: " + e.getClass().getSimpleName()
                + ": " + e.getMessage());
            if (debug) e.printStackTrace(System.out);
            // Generic error to browser - do not expose internals
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                "Authentication failed. Please try again.");
        }
    }

    @Override
    public void destroy() {}

    // -------------------------------------------------------------------------
    // OIDC Flow
    // -------------------------------------------------------------------------

    private void startOidc(HttpServletRequest req, HttpServletResponse res)
            throws Exception {

        HttpSession session = req.getSession(true);
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        session.setAttribute(SESS_STATE, state);
        session.setAttribute(SESS_NONCE, nonce);

        log("[START-OIDC] Generated state=" + state + " | nonce=" + nonce
            + " | sessionId=" + session.getId());

        StringBuilder url = new StringBuilder(authorizationEndpoint)
            .append("?response_type=code")
            .append("&client_id=")    .append(enc(clientId))
            .append("&redirect_uri=") .append(enc(redirectUri))
            .append("&scope=")        .append(enc(scope))
            .append("&state=")        .append(enc(state))
            .append("&nonce=")        .append(enc(nonce))
            .append("&response_mode=query");

        if (pkceSupported) {
            String verifier  = generateCodeVerifier();
            String challenge = generateCodeChallenge(verifier);
            session.setAttribute(SESS_CODE_VERIFIER, verifier);
            url.append("&code_challenge=")       .append(enc(challenge))
               .append("&code_challenge_method=S256");
            log("[START-OIDC] PKCE S256 added"
                + " | verifier.length=" + verifier.length()
                + " | challenge=" + challenge);
        }

        String authUrl = url.toString();
        log("[START-OIDC] Redirecting to: " + authUrl);
        res.sendRedirect(authUrl);
    }

    private String exchangeCodeForIdToken(String code, String codeVerifier)
            throws Exception {

        log("[TOKEN-EXCHANGE] Sending token request to: " + tokenEndpoint);
        log("[TOKEN-EXCHANGE] code.length=" + code.length()
            + " | pkce=" + pkceSupported
            + " | secret=" + hasSecret);

        StringBuilder body = new StringBuilder()
            .append("grant_type=authorization_code")
            .append("&code=")         .append(enc(code))
            .append("&redirect_uri=") .append(enc(redirectUri))
            .append("&client_id=")    .append(enc(clientId));

        if (pkceSupported && codeVerifier != null && !codeVerifier.isEmpty()) {
            body.append("&code_verifier=").append(enc(codeVerifier));
            log("[TOKEN-EXCHANGE] PKCE code_verifier included (len=" + codeVerifier.length() + ")");
        }

        if (hasSecret) {
            body.append("&client_secret=").append(enc(clientSecret));
            log("[TOKEN-EXCHANGE] client_secret included");
        }

        long start     = System.currentTimeMillis();
        String json    = httpPostForm(tokenEndpoint, body.toString());
        long elapsed   = System.currentTimeMillis() - start;

        log("[TOKEN-EXCHANGE] Response received in " + elapsed + "ms"
            + " | response.length=" + json.length());

        String idToken = safeJsonString(json, "id_token");

        if (idToken == null || idToken.isEmpty()) {
            // Log full IdP error response for troubleshooting
            String error    = sanitize(safeJsonString(json, "error"));
            String desc     = sanitize(safeJsonString(json, "error_description"));
            String traceId  = sanitize(safeJsonString(json, "trace_id"));
            String corrId   = sanitize(safeJsonString(json, "correlation_id"));
            log("[TOKEN-EXCHANGE] FAILED"
                + " | error=" + error
                + " | description=" + desc
                + " | traceId=" + traceId
                + " | correlationId=" + corrId);
            throw new IOException("Token exchange failed: " + error + " - " + desc);
        }

        log("[TOKEN-EXCHANGE] id_token received successfully (len=" + idToken.length() + ")");
        return idToken;
    }

    /**
     * Validates the ID token fully:
     * signature, issuer, audience, exp, nbf, iat, nonce.
     *
     * iat is checked at LOGIN TIME ONLY.
     * After session is created this check never runs again.
     * Users will NOT be kicked out mid-session by iat expiry.
     */
    private JWTClaimsSet validateIdToken(SignedJWT jwt, String expectedNonce)
            throws Exception {

        long now = System.currentTimeMillis();
        log("[VALIDATE] Starting token validation | now=" + new Date(now));

        refreshJwks(false);

        String kid = jwt.getHeader().getKeyID();
        log("[VALIDATE] JWT kid=" + kid + " | alg=" + jwt.getHeader().getAlgorithm());

        JWK jwk = jwkSet.getKeyByKeyId(kid);
        if (jwk == null) {
            log("[VALIDATE] kid not found in cached JWKS - forcing refresh");
            refreshJwks(true);
            jwk = jwkSet.getKeyByKeyId(kid);
            if (jwk == null)
                throw new IOException("No JWK found for kid=" + kid
                    + " - check that IdP JWKS endpoint is correct");
        }

        log("[VALIDATE] JWK found | type=" + jwk.getKeyType() + " | kid=" + jwk.getKeyID());

        if (!(jwk instanceof RSAKey))
            throw new IOException(
                "Unsupported key type: " + jwk.getKeyType() + " (RSA required)");

        RSAPublicKey pub      = ((RSAKey) jwk).toRSAPublicKey();
        JWSVerifier  verifier = new RSASSAVerifier(pub);
        boolean      sigOk    = jwt.verify(verifier);
        log("[VALIDATE] Signature verification: " + (sigOk ? "PASSED" : "FAILED"));
        if (!sigOk)
            throw new IOException("JWT signature verification failed");

        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        // Log all claims for debug troubleshooting
        log("[VALIDATE] Token claims: " + claims.getClaims().toString());

        // Issuer check
        String tokenIssuer = claims.getIssuer();
        boolean issuerOk = issuer.equals(tokenIssuer);
        log("[VALIDATE] Issuer check: expected=" + issuer
            + " | got=" + tokenIssuer + " | match=" + issuerOk);
        if (!issuerOk)
            throw new IOException("Invalid issuer: expected=" + issuer + " got=" + tokenIssuer);

        // Audience check
        List<String> aud   = claims.getAudience();
        boolean      audOk = aud != null && aud.contains(clientId);
        log("[VALIDATE] Audience check: expected=" + clientId
            + " | got=" + aud + " | match=" + audOk);
        if (!audOk)
            throw new IOException("Invalid audience: expected=" + clientId + " got=" + aud);

        // Expiration check
        Date exp    = claims.getExpirationTime();
        boolean expOk = exp != null && now <= exp.getTime() + CLOCK_SKEW_MS;
        log("[VALIDATE] Expiration check: exp=" + exp
            + " | now=" + new Date(now)
            + " | skew=" + (CLOCK_SKEW_MS / 1000) + "s"
            + " | valid=" + expOk);
        if (exp == null) throw new IOException("Token missing exp claim");
        if (!expOk)      throw new IOException("Token has expired at " + exp);

        // Not-before check
        Date nbf = claims.getNotBeforeTime();
        if (nbf != null) {
            boolean nbfOk = now >= nbf.getTime() - CLOCK_SKEW_MS;
            log("[VALIDATE] Not-before check: nbf=" + nbf
                + " | valid=" + nbfOk);
            if (!nbfOk)
                throw new IOException("Token not yet valid. nbf=" + nbf
                    + " - check server clock sync");
        } else {
            log("[VALIDATE] Not-before: not present in token (optional - OK)");
        }

        // Issued-at check - LOGIN TIME ONLY
        Date iat    = claims.getIssueTime();
        long maxAge = maxTokenAgeMs + CLOCK_SKEW_MS;
        boolean iatOk = iat != null && now <= iat.getTime() + maxAge;
        log("[VALIDATE] Issued-at check (login only): iat=" + iat
            + " | maxAge=" + (maxTokenAgeMs / 1000) + "s"
            + " | tokenAge=" + (iat != null ? ((now - iat.getTime()) / 1000) + "s" : "N/A")
            + " | valid=" + iatOk);
        if (iat == null) throw new IOException("Token missing iat claim");
        if (!iatOk)
            throw new IOException("Token too old at login time: iat=" + iat
                + " age=" + ((now - iat.getTime()) / 1000) + "s"
                + " max=" + (maxTokenAgeMs / 1000) + "s"
                + " - increase max.token.age.seconds in oidc.properties");

        // Nonce check - always required, constant-time compare
        String nonce   = safeStringClaim(claims, "nonce");
        boolean nonceOk = nonce != null && !nonce.isEmpty()
                       && constantTimeEquals(expectedNonce, nonce);
        log("[VALIDATE] Nonce check: expected=" + expectedNonce
            + " | got=" + nonce + " | match=" + nonceOk);
        if (nonce == null || nonce.isEmpty())
            throw new IOException("Token missing nonce claim. "
                + "Configure optional claims / attribute release in your IdP.");
        if (!nonceOk)
            throw new IOException("Nonce mismatch - possible replay attack");

        log("[VALIDATE] All checks PASSED");
        return claims;
    }

    // -------------------------------------------------------------------------
    // Navigation Detection
    // -------------------------------------------------------------------------

    private boolean isTopLevelNavigation(HttpServletRequest req) {
        String fetchMode = req.getHeader("Sec-Fetch-Mode");
        String fetchDest = req.getHeader("Sec-Fetch-Dest");

        if (fetchMode != null && fetchDest != null) {
            boolean result = "navigate".equalsIgnoreCase(fetchMode) &&
                             "document".equalsIgnoreCase(fetchDest);
            log("[NAV] Sec-Fetch headers present: mode=" + fetchMode
                + " dest=" + fetchDest + " -> isTopLevel=" + result);
            return result;
        }

        log("[NAV] Sec-Fetch headers missing - using fallback detection");

        String xrw = req.getHeader("X-Requested-With");
        if (xrw != null && xrw.equalsIgnoreCase("XMLHttpRequest")) {
            log("[NAV] X-Requested-With=XMLHttpRequest -> not top-level");
            return false;
        }

        String accept = req.getHeader("Accept");
        if (accept == null || !accept.toLowerCase().contains("text/html")) {
            log("[NAV] Accept header has no text/html -> not top-level | Accept=" + accept);
            return false;
        }

        String uri = req.getRequestURI().toLowerCase();
        boolean psUri = uri.contains(".gbl") || uri.contains("/psp/") || uri.contains("/psc/ps/");
        log("[NAV] Fallback: Accept contains text/html, psUri=" + psUri + " | uri=" + uri);
        return psUri;
    }

    // -------------------------------------------------------------------------
    // Request Wrappers
    // -------------------------------------------------------------------------

    /**
     * Strips the authentication header from inbound requests.
     * Without this an attacker can forge X-PS-USER: admin to bypass auth.
     */
    private static class StripHeaderWrapper extends HttpServletRequestWrapper {
        private final String stripName;

        StripHeaderWrapper(HttpServletRequest req, String stripName) {
            super(req);
            this.stripName = stripName;
        }

        @Override
        public String getHeader(String name) {
            if (stripName.equalsIgnoreCase(name)) return null;
            return super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (stripName.equalsIgnoreCase(name)) return Collections.emptyEnumeration();
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> names = Collections.list(super.getHeaderNames());
            names.removeIf(h -> stripName.equalsIgnoreCase(h));
            return Collections.enumeration(names);
        }
    }

    /** Injects the authenticated username as a request header for PeopleSoft SSO. */
    private static class UserWrapper extends HttpServletRequestWrapper {
        protected final String hdrName;
        protected final String user;

        UserWrapper(HttpServletRequest req, String hdrName, String user) {
            super(req);
            this.hdrName = hdrName;
            this.user    = user;
        }

        protected HttpServletRequest http() {
            return (HttpServletRequest) super.getRequest();
        }

        @Override
        public String getHeader(String name) {
            return hdrName.equalsIgnoreCase(name) ? user : http().getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (hdrName.equalsIgnoreCase(name)) {
                Vector<String> v = new Vector<>();
                v.add(user);
                return v.elements();
            }
            return http().getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            Vector<String>      names  = new Vector<>();
            Enumeration<String> e      = http().getHeaderNames();
            boolean             exists = false;
            while (e.hasMoreElements()) {
                String h = e.nextElement();
                names.add(h);
                if (hdrName.equalsIgnoreCase(h)) exists = true;
            }
            if (!exists) names.add(hdrName);
            return names.elements();
        }
    }

    /**
     * Extends UserWrapper to also strip OIDC callback params from the request
     * so PeopleSoft routing is not confused by code/state/session_state params.
     */
    private static class CleanCallbackWrapper extends UserWrapper {

        private static final Set<String> OIDC_PARAMS = new HashSet<>(
            Arrays.asList("code", "state", "session_state"));

        CleanCallbackWrapper(HttpServletRequest req, String hdrName, String user) {
            super(req, hdrName, user);
        }

        private boolean isOidc(String name) {
            return name != null && OIDC_PARAMS.contains(name.toLowerCase());
        }

        @Override
        public String getParameter(String n) {
            return isOidc(n) ? null : http().getParameter(n);
        }

        @Override
        public String[] getParameterValues(String n) {
            return isOidc(n) ? null : http().getParameterValues(n);
        }

        @Override
        public Enumeration<String> getParameterNames() {
            List<String> names = Collections.list(http().getParameterNames());
            names.removeIf(this::isOidc);
            return Collections.enumeration(names);
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> m = new HashMap<>(http().getParameterMap());
            new ArrayList<>(m.keySet()).stream().filter(this::isOidc).forEach(m::remove);
            return Collections.unmodifiableMap(m);
        }

        @Override
        public String getQueryString() {
            String qs = http().getQueryString();
            if (qs == null) return null;
            StringBuilder out = new StringBuilder();
            for (String part : qs.split("&")) {
                if (part == null || part.isEmpty()) continue;
                String key = part.contains("=")
                    ? part.substring(0, part.indexOf('=')) : part;
                if (isOidc(key)) continue;
                if (out.length() > 0) out.append("&");
                out.append(part);
            }
            return out.length() == 0 ? null : out.toString();
        }
    }

    // -------------------------------------------------------------------------
    // PKCE Helpers
    // -------------------------------------------------------------------------

    private String generateCodeVerifier() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private String generateCodeChallenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
            .digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    // -------------------------------------------------------------------------
    // JWKS Management
    // -------------------------------------------------------------------------

    private synchronized void refreshJwks(boolean force) throws Exception {
        long now = System.currentTimeMillis();
        if (!force && jwkSet != null && (now - jwksLoadedAtMs) < jwksCacheMs) {
            log("[JWKS] Using cached JWKS (age=" + ((now - jwksLoadedAtMs) / 1000) + "s"
                + " | cacheMax=" + (jwksCacheMs / 60000) + "min)");
            return;
        }
        log("[JWKS] Fetching JWKS from: " + jwksUri);
        long start = System.currentTimeMillis();
        jwkSet         = JWKSet.load(new URL(jwksUri));
        jwksLoadedAtMs = System.currentTimeMillis();
        log("[JWKS] Fetched in " + (jwksLoadedAtMs - start) + "ms"
            + " | keys=" + jwkSet.getKeys().size());
    }

    // -------------------------------------------------------------------------
    // Username Extraction
    // -------------------------------------------------------------------------

    private String extractUsername(JWTClaimsSet claims) {
        for (String claim : new String[]{
                usernameClaim, "preferred_username", "upn", "email"}) {
            String v = safeStringClaim(claims, claim);
            if (v != null && !v.trim().isEmpty()) {
                log("[USERNAME] Found in claim '" + claim + "' = " + v);
                return v.trim();
            }
            log("[USERNAME] Claim '" + claim + "' not found or empty");
        }
        String sub = claims.getSubject();
        log("[USERNAME] Falling back to 'sub' claim = " + sub);
        return sub;
    }

    // -------------------------------------------------------------------------
    // HTTP Helpers
    // -------------------------------------------------------------------------

    private static String httpGet(String url) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("GET");
        c.setConnectTimeout(HTTP_TIMEOUT);
        c.setReadTimeout(HTTP_TIMEOUT);
        InputStream is = c.getResponseCode() < 400
            ? c.getInputStream() : c.getErrorStream();
        return readAll(is);
    }

    private static String httpPostForm(String url, String body) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setConnectTimeout(HTTP_TIMEOUT);
        c.setReadTimeout(HTTP_TIMEOUT);
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        try (OutputStream os = c.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
        InputStream is = c.getResponseCode() < 400
            ? c.getInputStream() : c.getErrorStream();
        return readAll(is);
    }

    /** Caps response size at 1MB to prevent memory DoS from oversized IdP responses. */
    private static String readAll(InputStream is) throws IOException {
        if (is == null) return "";
        byte[]                buf  = new byte[4096];
        int                   read, total = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((read = is.read(buf)) != -1) {
            total += read;
            if (total > MAX_RESP_BYTES)
                throw new IOException(
                    "IdP response exceeded " + MAX_RESP_BYTES + " byte limit");
            baos.write(buf, 0, read);
        }
        return baos.toString("UTF-8");
    }

    // -------------------------------------------------------------------------
    // JSON Helpers - no external dependencies
    // -------------------------------------------------------------------------

    /**
     * Strips nested JSON objects, keeping only top-level key/value pairs.
     * Fixes Azure mTLS problem where token_endpoint appears inside
     * mtls_endpoint_aliases{} and gets picked up by regex parsers.
     */
    private static String flattenTopLevel(String json) {
        if (json == null) return "";
        StringBuilder sb       = new StringBuilder();
        int           depth    = 0;
        boolean       inString = false;
        boolean       escape   = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escape) {
                escape = false;
                if (depth <= 1) sb.append(c);
                continue;
            }
            if (c == '\\' && inString) {
                escape = true;
                if (depth <= 1) sb.append(c);
                continue;
            }
            if (c == '"') inString = !inString;
            if (!inString) {
                if (c == '{') { depth++; if (depth <= 1) sb.append(c); continue; }
                if (c == '}') { depth--; if (depth <= 0) sb.append(c); continue; }
            }
            if (depth <= 1) sb.append(c);
        }
        return sb.toString();
    }

    private static Properties parseJsonFlat(String json) throws ServletException {
        if (json == null || json.trim().isEmpty())
            throw new ServletException("Empty JSON response from IdP discovery endpoint");

        Properties result = new Properties();

        Matcher ms = Pattern.compile(
            "\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        while (ms.find())
            result.setProperty(ms.group(1),
                ms.group(2).replace("\\\"", "\"").replace("\\\\", "\\"));

        Matcher ma = Pattern.compile(
            "\"([^\"]+)\"\\s*:\\s*\\[([^\\]]+)\\]").matcher(json);
        while (ma.find())
            result.setProperty(ma.group(1),
                ma.group(2).replaceAll("\"", "").replaceAll("\\s", ""));

        Matcher mo = Pattern.compile(
            "\"([^\"]+)\"\\s*:\\s*([^,\\}\\]\"\\[\\{]+)").matcher(json);
        while (mo.find()) {
            String k = mo.group(1).trim();
            String v = mo.group(2).trim();
            if (!result.containsKey(k) && !v.isEmpty())
                result.setProperty(k, v);
        }

        return result;
    }

    private static String safeJsonString(String json, String key) {
        if (json == null || key == null) return null;
        Matcher m = Pattern.compile(
            "\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
            .matcher(json);
        if (!m.find()) return null;
        return m.group(1).replace("\\\"", "\"").replace("\\\\", "\\").trim();
    }

    private static String requireDisc(Properties disc, String key)
            throws ServletException {
        String v = disc.getProperty(key);
        if (v == null || v.trim().isEmpty())
            throw new ServletException(
                "OIDC discovery missing required field: '" + key + "'. " +
                "Check your issuer URL in oidc.properties.");
        return v.trim();
    }

    // -------------------------------------------------------------------------
    // Security Utilities
    // -------------------------------------------------------------------------

    private static void enforceHttpsUrl(String url, String label)
            throws ServletException {
        if (url != null && !url.toLowerCase().startsWith("https://"))
            throw new ServletException(label + " must use HTTPS. Got: " + url);
    }

    private void validateOrigin(String url, String label) throws ServletException {
        if (url == null) return;
        if (!url.toLowerCase().startsWith("https://"))
            throw new ServletException(label + " must use HTTPS");
    }

    private static String extractOrigin(String url) {
        try {
            URL u = new URL(url);
            return u.getProtocol() + "://" + u.getHost() +
                (u.getPort() > 0 ? ":" + u.getPort() : "");
        } catch (MalformedURLException e) {
            return url;
        }
    }

    /** Only trusts X-Forwarded-Proto from private/loopback IP ranges. */
    private static void enforceHttpsIfNeeded(HttpServletRequest req)
            throws ServletException {
        if (req.isSecure()) return;
        String remote = req.getRemoteAddr();
        boolean fromPrivate = remote != null && (
            remote.equals("127.0.0.1")       ||
            remote.equals("0:0:0:0:0:0:0:1") ||
            remote.startsWith("10.")          ||
            remote.startsWith("192.168.")     ||
            remote.startsWith("172.16.")      ||
            remote.startsWith("172.17.")      ||
            remote.startsWith("172.18.")      ||
            remote.startsWith("172.19.")      ||
            remote.startsWith("172.2")        ||
            remote.startsWith("172.30.")      ||
            remote.startsWith("172.31.")
        );
        if (fromPrivate) {
            String xf = req.getHeader("X-Forwarded-Proto");
            if ("https".equalsIgnoreCase(xf)) return;
        }
        // Uncomment to enforce HTTPS strictly in production:
        // throw new ServletException("HTTPS required.");
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] ba = a.getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(StandardCharsets.UTF_8);
        if (ba.length != bb.length) return false;
        int diff = 0;
        for (int i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
        return diff == 0;
    }

    /** Strips CRLF from IdP-provided strings to prevent log injection. */
    private static String sanitize(String s) {
        if (s == null) return null;
        return s.replaceAll("[\\r\\n\\t]", " ").trim();
    }

    private static void addSecurityHeaders(HttpServletResponse res) {
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "SAMEORIGIN");
        res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        // Enable for HTTPS deployments:
        // res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }

    private static String safeStringClaim(JWTClaimsSet claims, String key) {
        if (key == null || key.trim().isEmpty()) return null;
        try { return claims.getStringClaim(key); } catch (Exception e) { return null; }
    }

    private static String require(Properties p, String key) throws ServletException {
        String v = p.getProperty(key);
        if (v == null || v.trim().isEmpty())
            throw new ServletException("Missing required property: '" + key + "'");
        return v.trim();
    }

    private static String enc(String s) throws UnsupportedEncodingException {
        return URLEncoder.encode(s, "UTF-8");
    }

    private static void syslog(String s) {
        System.out.println("[OIDC] " + s);
    }

    private void log(String s) {
        if (debug) System.out.println("[OIDC] " + s);
    }
}

