/**
 * ZMONIE — reCAPTCHA backend verification (Firebase Cloud Functions)
 * ---------------------------------------------------------------
 * This is the ONLY place the Secret Key is ever used. It is read
 * from Firestore using the Admin SDK, which bypasses Firestore
 * security rules entirely — so this works even though the
 * `adminSettings/recaptchaSecret` document has NO read access
 * granted to anyone in the security rules (see firestore.rules
 * shipped alongside this file).
 *
 * Deploy with:
 *   cd functions
 *   npm install
 *   firebase deploy --only functions
 *
 * After deploying, the Super Admin can save/replace the Secret Key
 * at any time from Admin Settings → reCAPTCHA Settings in the app.
 * No further deploys are needed when the key changes — this
 * function reads the current value from Firestore on every call.
 */

const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();
const db = admin.firestore();

// Must match SUPER_ADMIN_EMAIL in index.html
const SUPER_ADMIN_EMAIL = 'oladejiridwanopeyemi@gmail.com';

async function getSecretKey() {
  const doc = await db.collection('adminSettings').doc('recaptchaSecret').get();
  if (!doc.exists) return null;
  return doc.data().secretKey || null;
}

async function callGoogleVerify(secret, token, remoteip) {
  const params = new URLSearchParams();
  params.append('secret', secret);
  params.append('response', token);
  if (remoteip) params.append('remoteip', remoteip);

  const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  return res.json();
}

/**
 * Called by the app on every protected form (login, registration,
 * forgot password, support). Verifies the token server-side.
 * Never returns the secret key — only a boolean success result.
 */
exports.verifyRecaptcha = functions.https.onCall(async (data, context) => {
  const token = data && data.token;
  const action = (data && data.action) || 'submit';

  if (!token) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing reCAPTCHA token.');
  }

  const statusDoc = await db.collection('adminSettings').doc('recaptchaStatus').get();
  const status = statusDoc.exists ? statusDoc.data() : { enabled: false, configured: false };

  // Protection is turned off by the admin — let the request through.
  if (!status.enabled) {
    return { success: true, skipped: true };
  }

  const secret = await getSecretKey();
  if (!secret) {
    // Protection is ON but no key is saved — fail closed, per spec.
    throw new functions.https.HttpsError(
      'failed-precondition',
      'reCAPTCHA is enabled but not fully configured. Please try again shortly.'
    );
  }

  const remoteip = context.rawRequest && context.rawRequest.ip;
  const result = await callGoogleVerify(secret, token, remoteip);

  if (!result.success) {
    throw new functions.https.HttpsError(
      'permission-denied',
      'reCAPTCHA verification failed. Please try again.',
      { errorCodes: result['error-codes'] || [] }
    );
  }

  return { success: true, action: result.action || action, score: result.score ?? null };
});

/**
 * Admin-only: lets the Super Admin confirm a saved Secret Key is
 * actually valid, without needing a real completed captcha widget.
 * Uses a throwaway token — Google will reject it either way, but
 * the *reason* it rejects tells us whether the SECRET itself is
 * valid ("invalid-input-secret" vs. anything else).
 */
exports.testRecaptchaSecret = functions.https.onCall(async (data, context) => {
  if (!context.auth || (context.auth.token.email || '').toLowerCase() !== SUPER_ADMIN_EMAIL) {
    throw new functions.https.HttpsError(
      'permission-denied',
      'Only the Super Admin can test the reCAPTCHA secret key.'
    );
  }

  const secret = await getSecretKey();
  if (!secret) {
    return { valid: false, message: 'No Secret Key has been saved yet.' };
  }

  const result = await callGoogleVerify(secret, 'test-dummy-token-for-key-validation-only');
  const errors = result['error-codes'] || [];

  if (errors.includes('invalid-input-secret')) {
    return { valid: false, message: 'This Secret Key is invalid. Double-check it and save again.' };
  }

  // Any other error (e.g. invalid-input-response, timeout-or-duplicate)
  // means Google accepted the SECRET and rejected only the dummy token —
  // which is exactly what we expect. The secret itself is good.
  return { valid: true, message: 'Secret Key is valid and recognized by Google.' };
});
