import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { QRCodeSVG } from 'qrcode.react';

async function request(path, body) {
  const response = await fetch(`/api${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    credentials: 'include',
    headers: body === undefined ? {} : {
      'Content-Type': 'application/json',
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const data = await response.json();

  if (!response.ok) {
    const details = Array.isArray(data.details)
      ? data.details.join(' ')
      : '';

    const message = response.status === 429
      ? 'Too many attempts. Wait for the cooldown before trying again.'
      : [data.error || data.message || 'Request failed.', details]
          .filter(Boolean).join(' ');

    throw new Error(message);
  }

  return data;
}

function App() {
  const [screen, setScreen] = useState('login');
  const [user, setUser] = useState(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(true);
  const [enrollmentUri, setEnrollmentUri] = useState('');

  useEffect(() => {
    let active = true;

    async function checkSession() {
      try {
        const data = await request('/me');
        if (active) setUser(data);
      } catch {
        // The login form is available when there is no active session.
      } finally {
        if (active) setBusy(false);
      }
    }

    checkSession();
    return () => { active = false; };
  }, []);

  async function submit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);

    setBusy(true);
    setMessage('');

    try {
      if (screen === 'verify') {
        await request('/mfa/verify', {
          token: fields.get('token'),
        });
        form.reset();
        setUser(await request('/me'));
        setScreen('login');
        return;
      }

      const data = await request(`/${screen}`, {
        email: fields.get('email'),
        password: fields.get('password'),
      });

      form.reset();

      if (screen === 'register') {
        setScreen('login');
        setMessage('Account created. Sign in with your new account.');
      } else if (data.mfaRequired) {
        setScreen('verify');
        setMessage('Enter the current code from your authenticator app.');
      } else {
        setUser(await request('/me'));
      }
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function logout() {
    setBusy(true);
    setMessage('');

    try {
      await request('/logout', {});
      setUser(null);
      setScreen('login');
      setMessage('Signed out.');
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }
  
  async function startEnrollment() {
  setBusy(true);
  setMessage('');

  try {
    const data = await request('/mfa/enroll', {});

    if (typeof data.uri !== 'string' || !data.uri.startsWith('otpauth://')) {
      throw new Error('The server returned an invalid setup response.');
    }

    setEnrollmentUri(data.uri);
  } catch (error) {
    setMessage(error.message);
  } finally {
    setBusy(false);
  }
}

async function confirmEnrollment(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const fields = new FormData(form);

  setBusy(true);
  setMessage('');

  try {
    await request('/mfa/confirm', {
      token: fields.get('token'),
    });

    form.reset();
    setEnrollmentUri('');
    setMessage(
      'Authenticator enabled. Before testing login, wait for a fresh code.'
    );
  } catch (error) {
    setMessage(error.message);
  } finally {
    setBusy(false);
  }
}

  function changeScreen(next) {
    setScreen(next);
    setMessage('');
  }

  return (
    <main style={{
      maxWidth: 440,
      margin: '60px auto',
      padding: 24,
      fontFamily: 'system-ui, sans-serif',
      lineHeight: 1.6,
    }}>
      <h1>Authentication Security</h1>

      {user ? (
        <section>
          <h2>You are signed in</h2>
          <p>Your session was confirmed by the protected /me route.</p>

{enrollmentUri ? (
  <section>
    <h3>Set up your authenticator</h3>
    <p>
      In your authenticator app, add an account by scanning this QR code.
      Then enter its current six-digit code below.
    </p>

    <QRCodeSVG
      value={enrollmentUri}
      size={220}
      marginSize={4}
      title="Authenticator enrollment QR code"
    />

    <form onSubmit={confirmEnrollment}>
      <label htmlFor="setup-token">Authenticator code</label>
      <input
        id="setup-token"
        name="token"
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9]{6}"
        maxLength={6}
        required
        disabled={busy}
        style={inputStyle}
      />

      <button type="submit" disabled={busy}>
        {busy ? 'Please wait…' : 'Confirm authenticator'}
      </button>
    </form>
  </section>
) : (
  <p>
    <button onClick={startEnrollment} disabled={busy}>
      Set up authenticator
    </button>
  </p>
)}

<p>
  <button
    onClick={() => {
      setEnrollmentUri('');
      logout();
    }}
    disabled={busy}
  >
    Sign out
  </button>
</p>
        </section>
      ) : (
        <>
          <h2>
            {screen === 'register' ? 'Create an account'
              : screen === 'verify' ? 'Authenticator code'
              : 'Sign in'}
          </h2>

          <form key={screen} onSubmit={submit}>
            <fieldset disabled={busy} style={{ border: 0, padding: 0 }}>
              {screen === 'verify' ? (
                <>
                  <label htmlFor="token">Six-digit code</label>
                  <input
                    id="token"
                    name="token"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    required
                    style={inputStyle}
                  />
                </>
              ) : (
                <>
                  <label htmlFor="email">Email</label>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="username"
                    required
                    style={inputStyle}
                  />

                  <label htmlFor="password">Password</label>
                  <input
                    id="password"
                    name="password"
                    type="password"
                    autoComplete={
                      screen === 'register'
                        ? 'new-password' : 'current-password'
                    }
                    required
                    style={inputStyle}
                  />

                  {screen === 'register' && (
                    <p>
                      Use 15–128 characters with uppercase and lowercase
                      letters, a number, and a symbol.
                    </p>
                  )}
                </>
              )}

              <button type="submit">
                {busy ? 'Please wait…'
                  : screen === 'register' ? 'Create account'
                  : screen === 'verify' ? 'Verify code' : 'Sign in'}
              </button>
            </fieldset>
          </form>

          <p>
            <button
              type="button"
              disabled={busy}
              onClick={() => changeScreen(
                screen === 'login' ? 'register' : 'login'
              )}
            >
              {screen === 'login'
                ? 'Create a new account' : 'Back to sign in'}
            </button>
          </p>
        </>
      )}

      <p role="status">{message}</p>
    </main>
  );
}

const inputStyle = {
  display: 'block',
  boxSizing: 'border-box',
  width: '100%',
  padding: 10,
  marginBottom: 16,
};

createRoot(document.getElementById('root')).render(<App />);