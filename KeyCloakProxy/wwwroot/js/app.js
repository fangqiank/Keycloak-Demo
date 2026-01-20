// SECURE PORTAL - Main Application

// Redirect to Keycloak login
async function keycloakLogin() {
    console.log('[Auth] Initiating login sequence...');
    try {
        // Check for required browser features
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('Secure context required. Crypto API is not available. Please use HTTPS or localhost.');
        }

        // Generate PKCE
        console.log('[Auth] Generating PKCE...');
        const { codeVerifier, codeChallenge } = await generatePKCE();
        const state = generateState();

        // Store for callback
        sessionStorage.setItem('codeVerifier', codeVerifier);
        sessionStorage.setItem('state', state);

        // Build authorization URL
        const params = new URLSearchParams({
            client_id: CONFIG.keycloak.clientId,
            response_type: 'code',
            scope: CONFIG.keycloak.scope,
            redirect_uri: CONFIG.redirectUri,
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });

        const authUrl = `${CONFIG.authEndpoint}?${params.toString()}`;
        console.log('[Auth] Redirecting to Keycloak:', authUrl);

        window.location.href = authUrl;
    } catch (error) {
        console.error('[Auth] Login failed:', error);
        alert('Login Error: ' + error.message);
    }
}

// Handle OAuth2 callback (from Keycloak redirect)
async function handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const storedState = sessionStorage.getItem('state');

    // Verify state
    if (state !== storedState) {
        console.error('[Auth] State mismatch!');
        alert('Authentication Error: State mismatch. Possible CSRF attack or session expired.');
        // window.location.href = '/index.html';
        return;
    }

    if (!code) {
        console.error('[Auth] No authorization code received');
        alert('Authentication Error: No authorization code received.');
        // window.location.href = '/index.html';
        return;
    }

    try {
        // Exchange code for token
        const codeVerifier = sessionStorage.getItem('codeVerifier');
        console.log('[Auth] CodeVerifier:', codeVerifier ? 'exists' : 'missing');
        console.log('[Auth] Authorization code:', code ? 'exists' : 'missing');

        const tokenResponse = await exchangeCodeForToken(code, codeVerifier);
        console.log('[Auth] Token response received:', tokenResponse);

        // Check if response has expected fields
        if (!tokenResponse.access_token) {
            throw new Error('No access_token in response');
        }

        // Store token
        localStorage.setItem('accessToken', tokenResponse.access_token);
        localStorage.setItem('refreshToken', tokenResponse.refresh_token || '');
        localStorage.setItem('idToken', tokenResponse.id_token || '');

        console.log('[Auth] Tokens stored successfully');

        // Clean up
        sessionStorage.removeItem('codeVerifier');
        sessionStorage.removeItem('state');

        // Redirect to dashboard (remove query params)
        window.location.href = '/dashboard.html';
    } catch (error) {
        console.error('[Auth] Token exchange failed:', error);
        console.error('[Auth] Error stack:', error.stack);
        alert('Authentication Failed: ' + error.message);
        // window.location.href = '/index.html';
    }
}

// Exchange authorization code for access token via backend proxy
async function exchangeCodeForToken(code, codeVerifier) {
    const response = await fetch(window.location.origin + '/api/auth/callback', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            code: code,
            codeVerifier: codeVerifier,
            redirectUri: CONFIG.redirectUri
        })
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
        const errorMsg = error.error || error.message || JSON.stringify(error);
        console.error('[Auth] Full error response:', error);
        throw new Error(`Token exchange failed: ${errorMsg}`);
    }

    return await response.json();
}

// Logout from Keycloak and clear local session
async function logout() {
    const refreshToken = localStorage.getItem('refreshToken');

    // Call Keycloak logout endpoint
    if (refreshToken) {
        try {
            await fetch(CONFIG.logoutEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    client_id: CONFIG.keycloak.clientId,
                    refresh_token: refreshToken
                })
            });
        } catch (error) {
            console.error('[Auth] Keycloak logout failed:', error);
        }
    }

    // Clear local storage
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('idToken');

    // Redirect to home
    window.location.href = '/index.html';
}

// Refresh access token using refresh token
async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('refreshToken');

    if (!refreshToken) {
        throw new Error('No refresh token available');
    }

    const response = await fetch(CONFIG.tokenEndpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: CONFIG.keycloak.clientId,
            refresh_token: refreshToken
        })
    });

    if (!response.ok) {
        throw new Error('Token refresh failed');
    }

    const data = await response.json();
    localStorage.setItem('accessToken', data.access_token);
    if (data.refresh_token) {
        localStorage.setItem('refreshToken', data.refresh_token);
    }

    return data.access_token;
}

// Check if current page is a callback from Keycloak
if (window.location.search.includes('code=')) {
    handleCallback();
}

// Utility: Get access token with auto-refresh
async function getAccessToken() {
    let token = localStorage.getItem('accessToken');

    if (!token) {
        return null;
    }

    // Check if token is expired
    try {
        const claims = JSON.parse(atob(token.split('.')[1]));
        const exp = claims.exp * 1000;
        const now = Date.now();

        // Refresh if token expires in less than 5 minutes
        if (exp - now < 300000) {
            console.log('[Auth] Token expiring soon, refreshing...');
            token = await refreshAccessToken();
        }

        return token;
    } catch (error) {
        console.error('[Auth] Token validation failed:', error);
        return null;
    }
}

// Utility: Make authenticated API call
async function authenticatedFetch(url, options = {}) {
    const token = await getAccessToken();

    if (!token) {
        throw new Error('No valid access token');
    }

    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`
    };

    return fetch(url, { ...options, headers });
}

// Export for global access
window.keycloakLogin = keycloakLogin;
window.logout = logout;
window.authenticatedFetch = authenticatedFetch;
window.getAccessToken = getAccessToken;
