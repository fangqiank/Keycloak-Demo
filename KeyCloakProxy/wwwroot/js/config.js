// SECURE PORTAL - Configuration

const CONFIG = {
    // Keycloak Configuration
    keycloak: {
        authority: 'http://192.168.1.30:8080/realms/myrealm',
        clientId: 'private',
        responseType: 'code',
        scope: 'openid profile email'
    },

    // API Endpoints - use backend proxy to avoid CORS
    api: {
        baseUrl: window.location.origin,
        token: '/api/auth/callback',
        validate: '/auth/validate',
        roles: '/auth/roles',
        logout: '/api/auth/logout'
    },

    // OAuth2 Redirect
    redirectUri: 'http://localhost:5000/dashboard.html',

    // Keycloak Endpoints (constructed from authority)
    get authEndpoint() {
        return `${this.keycloak.authority}/protocol/openid-connect/auth`;
    },

    // These are for backend use only
    get tokenEndpoint() {
        return `${this.keycloak.authority}/protocol/openid-connect/token`;
    },

    get logoutEndpoint() {
        return `${this.keycloak.authority}/protocol/openid-connect/logout`;
    }
};

// Generate random state for CSRF protection
function generateState() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

// Generate PKCE code verifier and challenge
async function generatePKCE() {
    // Code verifier: random string 43-128 characters
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const codeVerifier = base64UrlEncode(array);

    // Code challenge: SHA256 hash of code verifier
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const codeChallenge = base64UrlEncode(hash);

    return { codeVerifier, codeChallenge };
}

function base64UrlEncode(buffer) {
    let str = String.fromCharCode.apply(null, new Uint8Array(buffer));
    let base64 = btoa(str);
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
