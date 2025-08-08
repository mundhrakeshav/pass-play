'use client';

import { useState, useEffect } from 'react';
import styles from "./page.module.css";

// TypeScript interfaces for WebAuthn
interface CredentialDescriptor {
  id: string;
  type: string;
}

// Base64URL encode/decode helpers
function base64URLEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64URLDecode(str: string): ArrayBuffer {
  if (!str || typeof str !== 'string') {
    throw new Error('Invalid base64URL string');
  }
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  const binary = atob(str);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return buffer;
}

export default function Home() {
  const [username, setUsername] = useState('testuser');
  const [status, setStatus] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [serverUrl, setServerUrl] = useState('http://192.168.29.216:8080');
  const [currentUrl, setCurrentUrl] = useState('');
  const [isSecureContext, setIsSecureContext] = useState(false);
  
  useEffect(() => {
    // Auto-detect server URL based on current environment
    const currentHost = window.location.hostname;
    if (currentHost === 'localhost' || currentHost === '127.0.0.1') {
      setServerUrl('http://localhost:8080');
    } else if (currentHost.includes('ngrok')) {
      // When using ngrok frontend, use the same-origin API proxy routes
      setServerUrl('/api');
    } else {
      // Use the server IP for network access
      setServerUrl('http://192.168.29.216:8080');
    }
    
    setCurrentUrl(window.location.href);
    setIsSecureContext(window.isSecureContext);
  }, []);

  const handleRegister = async () => {
    if (!username.trim()) {
      setStatus('Please enter a username');
      return;
    }

    // Check WebAuthn support
    if (!navigator.credentials) {
      setStatus('❌ WebAuthn not supported: navigator.credentials is not available');
      return;
    }

    if (!navigator.credentials.create) {
      setStatus('❌ WebAuthn not supported: navigator.credentials.create is not available. This usually means you need HTTPS.');
      return;
    }

    if (!window.isSecureContext) {
      setStatus('❌ WebAuthn requires a secure context (HTTPS or localhost). Current URL needs HTTPS.');
      return;
    }

    setIsLoading(true);
    setStatus('Starting registration...');

    try {
      // Begin registration
      const beginResponse = await fetch(`${serverUrl}/register/begin?username=${encodeURIComponent(username)}`);
      const beginData = await beginResponse.json();

      console.log('Begin registration response:', beginData);

      if (!beginResponse.ok) {
        throw new Error(beginData.error || 'Failed to begin registration');
      }

      setStatus('Please complete passkey registration on your device...');

      // Validate response structure (newer WebAuthn library wraps options in publicKey)
      const publicKeyOptions = beginData.options.publicKey || beginData.options;
      
      // Debug: Check each field individually
      console.log('publicKeyOptions:', publicKeyOptions);
      console.log('challenge exists:', !!publicKeyOptions?.challenge);
      console.log('user exists:', !!publicKeyOptions?.user);
      console.log('user.id exists:', !!publicKeyOptions?.user?.id);
      
      if (!publicKeyOptions) {
        throw new Error('Invalid response: publicKeyOptions is missing');
      }
      if (!publicKeyOptions.challenge) {
        throw new Error('Invalid response: challenge is missing');
      }
      if (!publicKeyOptions.user) {
        throw new Error('Invalid response: user is missing');
      }
      if (!publicKeyOptions.user.id) {
        throw new Error('Invalid response: user.id is missing');
      }

      // Prepare credential creation options
      const credentialCreationOptions = {
        ...publicKeyOptions,
        challenge: base64URLDecode(publicKeyOptions.challenge),
        user: {
          ...publicKeyOptions.user,
          id: base64URLDecode(publicKeyOptions.user.id),
        },
        excludeCredentials: publicKeyOptions.excludeCredentials?.map((cred: CredentialDescriptor) => ({
          ...cred,
          id: base64URLDecode(cred.id),
        })) || [],
      };

      // Create credential
      const credential = await navigator.credentials.create({
        publicKey: credentialCreationOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Failed to create credential');
      }

      setStatus('Finishing registration...');

      // Prepare credential for sending to server
      const credentialForServer = {
        id: credential.id,
        rawId: base64URLEncode(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: base64URLEncode((credential.response as AuthenticatorAttestationResponse).attestationObject),
          clientDataJSON: base64URLEncode(credential.response.clientDataJSON),
        },
      };

      // Finish registration
      const finishResponse = await fetch(`${serverUrl}/register/finish?sessionId=${beginData.sessionId}&username=${encodeURIComponent(username)}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentialForServer),
      });

      const finishData = await finishResponse.json();

      if (!finishResponse.ok) {
        throw new Error(finishData.error || 'Failed to finish registration');
      }

      setStatus('✅ Passkey registered successfully!');
    } catch (error: unknown) {
      console.error('Registration error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      setStatus(`❌ Registration failed: ${errorMessage}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAuthenticate = async () => {
    if (!username.trim()) {
      setStatus('Please enter a username');
      return;
    }

    // Check WebAuthn support
    if (!navigator.credentials) {
      setStatus('❌ WebAuthn not supported: navigator.credentials is not available');
      return;
    }

    if (!navigator.credentials.get) {
      setStatus('❌ WebAuthn not supported: navigator.credentials.get is not available. This usually means you need HTTPS.');
      return;
    }

    if (!window.isSecureContext) {
      setStatus('❌ WebAuthn requires a secure context (HTTPS or localhost). Current URL needs HTTPS.');
      return;
    }

    setIsLoading(true);
    setStatus('Starting authentication...');

    try {
      // Begin login
      const beginResponse = await fetch(`${serverUrl}/login/begin?username=${encodeURIComponent(username)}`);
      const beginData = await beginResponse.json();

      console.log('Begin login response:', beginData);

      if (!beginResponse.ok) {
        throw new Error(beginData.error || 'Failed to begin login');
      }

      setStatus('Please complete passkey authentication on your device...');

      // Validate response structure (newer WebAuthn library wraps options in publicKey)
      const publicKeyOptions = beginData.options.publicKey || beginData.options;
      if (!publicKeyOptions || !publicKeyOptions.challenge) {
        throw new Error('Invalid response from server: missing required fields');
      }

      // Prepare credential request options
      const credentialRequestOptions = {
        ...publicKeyOptions,
        challenge: base64URLDecode(publicKeyOptions.challenge),
        allowCredentials: publicKeyOptions.allowCredentials?.map((cred: CredentialDescriptor) => ({
          ...cred,
          id: base64URLDecode(cred.id),
        })) || [],
      };

      // Get credential
      const credential = await navigator.credentials.get({
        publicKey: credentialRequestOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Failed to get credential');
      }

      setStatus('Finishing authentication...');

      // Prepare credential for sending to server
      const credentialForServer = {
        id: credential.id,
        rawId: base64URLEncode(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: base64URLEncode((credential.response as AuthenticatorAssertionResponse).authenticatorData),
          clientDataJSON: base64URLEncode(credential.response.clientDataJSON),
          signature: base64URLEncode((credential.response as AuthenticatorAssertionResponse).signature),
          userHandle: (credential.response as AuthenticatorAssertionResponse).userHandle 
            ? base64URLEncode((credential.response as AuthenticatorAssertionResponse).userHandle!) 
            : undefined,
        },
      };

      // Finish login
      const finishResponse = await fetch(`${serverUrl}/login/finish?sessionId=${beginData.sessionId}&username=${encodeURIComponent(username)}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentialForServer),
      });

      const finishData = await finishResponse.json();

      if (!finishResponse.ok) {
        throw new Error(finishData.error || 'Failed to finish login');
      }

      setStatus('✅ Authentication successful!');
    } catch (error: unknown) {
      console.error('Authentication error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      setStatus(`❌ Authentication failed: ${errorMessage}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDiscoverableLogin = async () => {
    // Check WebAuthn support
    if (!navigator.credentials) {
      setStatus('❌ WebAuthn not supported: navigator.credentials is not available');
      return;
    }

    if (!navigator.credentials.get) {
      setStatus('❌ WebAuthn not supported: navigator.credentials.get is not available. This usually means you need HTTPS.');
      return;
    }

    if (!window.isSecureContext) {
      setStatus('❌ WebAuthn requires a secure context (HTTPS or localhost). Current URL needs HTTPS.');
      return;
    }

    setIsLoading(true);
    setStatus('Starting discoverable login...');

    try {
      // Begin discoverable login
      const beginResponse = await fetch(`${serverUrl}/login/discoverable/begin`);
      const beginData = await beginResponse.json();

      console.log('Begin discoverable login response:', beginData);

      if (!beginResponse.ok) {
        throw new Error(beginData.error || 'Failed to begin discoverable login');
      }

      setStatus('Please select and authenticate with your passkey...');

      // Validate response structure
      const publicKeyOptions = beginData.options.publicKey || beginData.options;
      if (!publicKeyOptions || !publicKeyOptions.challenge) {
        throw new Error('Invalid response from server: missing required fields');
      }

      // Prepare credential request options for discoverable login
      // For discoverable login, we don't specify allowCredentials
      const credentialRequestOptions = {
        ...publicKeyOptions,
        challenge: base64URLDecode(publicKeyOptions.challenge),
        // Don't include allowCredentials for discoverable login
        // This lets the authenticator show all available passkeys
      };

      console.log('Credential request options:', credentialRequestOptions);

      // Get credential - this will show the user's available passkeys
      const credential = await navigator.credentials.get({
        publicKey: credentialRequestOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Failed to get credential');
      }

      setStatus('Finishing authentication...');

      // Prepare credential for sending to server
      const credentialForServer = {
        id: credential.id,
        rawId: base64URLEncode(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: base64URLEncode((credential.response as AuthenticatorAssertionResponse).authenticatorData),
          clientDataJSON: base64URLEncode(credential.response.clientDataJSON),
          signature: base64URLEncode((credential.response as AuthenticatorAssertionResponse).signature),
          userHandle: (credential.response as AuthenticatorAssertionResponse).userHandle 
            ? base64URLEncode((credential.response as AuthenticatorAssertionResponse).userHandle!) 
            : undefined,
        },
      };

      // Finish discoverable login (no username needed)
      const finishResponse = await fetch(`${serverUrl}/login/discoverable/finish?sessionId=${beginData.sessionId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentialForServer),
      });

      const finishData = await finishResponse.json();

      if (!finishResponse.ok) {
        throw new Error(finishData.error || 'Failed to finish discoverable login');
      }
      
      console.log('Finish discoverable login response:', finishData);
      await new Promise(resolve => setTimeout(resolve, 10000));
      console.log('Redo the same request again');
      
      // Finish discoverable login (no username needed)
      const finishResponse2 = await fetch(`${serverUrl}/login/discoverable/finish?sessionId=${beginData.sessionId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentialForServer),
      });

      const finishData2 = await finishResponse2.json();

      if (!finishResponse2.ok) {
        throw new Error(finishData.error || 'Failed to finish discoverable login');
      }

      console.log('Finish discoverable login response:', finishData2);


      const authenticatedUsername = finishData.username || 'Unknown User';
      setStatus(`✅ Welcome back, ${authenticatedUsername}! Authentication successful!`);
    } catch (error: unknown) {
      console.error('Discoverable authentication error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      setStatus(`❌ Discoverable authentication failed: ${errorMessage}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={styles.page}>
      <main className={styles.main}>
        <h1>Passkey Demo</h1>
        
        <div className={styles.inputGroup}>
          <label htmlFor="username">Username:</label>
          <input
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username"
            disabled={isLoading}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button 
            onClick={handleRegister}
            disabled={isLoading}
            className={styles.registerButton}
          >
            {isLoading ? 'Processing...' : 'Register Passkey'}
          </button>
          
          <button 
            onClick={handleAuthenticate}
            disabled={isLoading}
            className={styles.authButton}
          >
            {isLoading ? 'Processing...' : 'Authenticate with Passkey'}
          </button>

          <button 
            onClick={handleDiscoverableLogin}
            disabled={isLoading}
            className={styles.discoverableButton}
          >
            {isLoading ? 'Processing...' : '🔍 Login with Passkey (No Username)'}
          </button>
        </div>

        {status && (
          <div className={styles.status}>
            {status}
          </div>
        )}

        <div className={styles.instructions}>
          <h3>Instructions:</h3>
          <h4>Traditional Flow:</h4>
          <ol>
            <li>Enter a username</li>
            <li>Click &quot;Register Passkey&quot; to create a new passkey on your device</li>
            <li>Click &quot;Authenticate with Passkey&quot; to verify using your stored passkey</li>
          </ol>
          
          <h4>🆕 Discoverable Credentials (Resident Keys):</h4>
          <ol>
            <li>First register a passkey using the traditional flow above</li>
            <li>Click &quot;🔍 Login with Passkey (No Username)&quot; to authenticate without entering a username</li>
            <li>Your device will show all available passkeys with usernames - select one to login</li>
          </ol>
          
          <div style={{marginTop: '20px', padding: '10px', backgroundColor: '#d4edda', border: '1px solid #c3e6cb', borderRadius: '5px'}}>
            <strong>🔒 WebAuthn Status:</strong>
            <p><small>Current URL: {currentUrl || 'Loading...'}</small></p>
            <p><small>Secure Context: {isSecureContext ? '✅ Yes' : '❌ No'}</small></p>
            <p><small>Backend: {serverUrl}</small></p>
            {currentUrl.includes('ngrok') && (
              <p style={{color: '#155724', fontWeight: 'bold'}}>✅ Using ngrok HTTPS tunnel - WebAuthn should work!</p>
            )}
            {!isSecureContext && !currentUrl.includes('localhost') && (
              <p style={{color: '#721c24', fontWeight: 'bold'}}>⚠️ WebAuthn requires HTTPS. Use ngrok or access via localhost.</p>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
