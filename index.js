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

// ================================================================
// FLUTTERWAVE — server-side verification
// ----------------------------------------------------------------
// The Secret Key, Encryption Key, and Webhook Secret Hash live only
// in `adminSettings/flutterwaveSecrets`, a Firestore document with
// NO read access for anyone (see firestore.rules snippet). Only
// this Cloud Function's Admin SDK can read it.
//
// Two independent paths credit the wallet, both idempotent against
// the same tx_ref so a payment is never credited twice:
//   1. verifyFlutterwaveTransaction — called by the browser right
//      after the inline checkout closes (fast, good UX).
//   2. flutterwaveWebhook — called by Flutterwave's own servers
//      (the authoritative source of truth; works even if the user
//      closes their browser before the app can call #1).
// ================================================================

const FLW_API = 'https://api.flutterwave.com/v3';

async function getFlutterwaveSecrets() {
  const doc = await db.collection('adminSettings').doc('flutterwaveSecrets').get();
  return doc.exists ? doc.data() : null;
}

async function getFlutterwaveStatus() {
  const doc = await db.collection('adminSettings').doc('flutterwaveStatus').get();
  return doc.exists ? doc.data() : { enabled: false, configured: false };
}

async function flwVerifyByTransactionId(secretKey, transactionId) {
  const res = await fetch(`${FLW_API}/transactions/${transactionId}/verify`, {
    headers: { Authorization: `Bearer ${secretKey}` },
  });
  return res.json();
}

/**
 * Credits a wallet for a verified Flutterwave transaction exactly
 * once, no matter how many times this is called for the same
 * tx_ref (webhook + client callback both racing is expected).
 */
async function creditWalletForFlutterwaveTx({ userId, txRef, amount, flwRef }) {
  const ledgerRef = db.collection('flutterwaveTx').doc(txRef);
  const result = await db.runTransaction(async (t) => {
    const ledgerDoc = await t.get(ledgerRef);
    if (ledgerDoc.exists && ledgerDoc.data().processed) {
      return { alreadyProcessed: true };
    }
    const userRef = db.collection('users').doc(userId);
    t.update(userRef, {
      balance: admin.firestore.FieldValue.increment(amount),
      hasFundedFirst: true,
    });
    t.set(ledgerRef, {
      processed: true,
      userId,
      amount,
      flwRef: flwRef || null,
      creditedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    const txDocRef = db.collection('transactions').doc();
    t.set(txDocRef, {
      userId,
      type: 'credit',
      amount,
      description: `Wallet Funded via Flutterwave (Ref: ${txRef})`,
      status: 'success',
      flutterwaveRef: flwRef || txRef,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return { alreadyProcessed: false };
  });
  return result;
}

/**
 * Called by the browser right after Flutterwave's inline checkout
 * closes. Re-verifies with Flutterwave's own API before crediting
 * anything — the client's local "success" callback is never trusted
 * on its own.
 */
exports.verifyFlutterwaveTransaction = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'You must be logged in.');
  }
  const { transaction_id, tx_ref, expectedAmount } = data || {};
  if (!transaction_id || !tx_ref) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing transaction reference.');
  }

  const status = await getFlutterwaveStatus();
  if (!status.enabled) {
    throw new functions.https.HttpsError('failed-precondition', 'Flutterwave is currently disabled.');
  }

  const secrets = await getFlutterwaveSecrets();
  if (!secrets || !secrets.secretKey) {
    throw new functions.https.HttpsError('failed-precondition', 'Flutterwave is not fully configured.');
  }

  const result = await flwVerifyByTransactionId(secrets.secretKey, transaction_id);
  const txData = result && result.data;

  if (!txData || result.status !== 'success' || txData.status !== 'successful') {
    throw new functions.https.HttpsError('permission-denied', 'Payment could not be verified.');
  }
  if (txData.tx_ref !== tx_ref) {
    throw new functions.https.HttpsError('permission-denied', 'Transaction reference mismatch.');
  }
  if (txData.currency !== 'NGN') {
    throw new functions.https.HttpsError('permission-denied', 'Unexpected currency.');
  }
  if (typeof expectedAmount === 'number' && txData.amount < expectedAmount) {
    throw new functions.https.HttpsError('permission-denied', 'Amount paid does not match amount requested.');
  }
  // Make sure the payment belongs to the caller, not someone else's meta.userId.
  if (txData.meta && txData.meta.userId && txData.meta.userId !== context.auth.uid) {
    throw new functions.https.HttpsError('permission-denied', 'Transaction does not belong to this account.');
  }

  const { alreadyProcessed } = await creditWalletForFlutterwaveTx({
    userId: context.auth.uid,
    txRef: tx_ref,
    amount: txData.amount,
    flwRef: txData.flw_ref,
  });

  return { success: true, amount: txData.amount, alreadyProcessed };
});

/**
 * Flutterwave's server-to-server webhook — the authoritative
 * confirmation path. Verifies the `verif-hash` header against the
 * Webhook Secret Hash saved in Admin Settings, then re-confirms via
 * the verify API before crediting (never trusts the raw payload).
 */
exports.flutterwaveWebhook = functions.https.onRequest(async (req, res) => {
  try {
    const secrets = await getFlutterwaveSecrets();
    if (!secrets || !secrets.webhookSecretHash) {
      res.status(401).send('Webhook not configured');
      return;
    }
    const signature = req.headers['verif-hash'];
    if (!signature || signature !== secrets.webhookSecretHash) {
      res.status(401).send('Invalid signature');
      return;
    }

    const event = req.body;
    const txData = event && event.data;
    if (!txData || event.event !== 'charge.completed' || txData.status !== 'successful') {
      res.status(200).send('Ignored'); // Ack anyway so Flutterwave doesn't retry forever.
      return;
    }

    // Re-verify via API rather than trusting the webhook body directly.
    const verifyResult = await flwVerifyByTransactionId(secrets.secretKey, txData.id);
    const verified = verifyResult && verifyResult.data;
    if (!verified || verifyResult.status !== 'success' || verified.status !== 'successful') {
      res.status(200).send('Could not re-verify');
      return;
    }

    const userId = verified.meta && verified.meta.userId;
    if (!userId) {
      res.status(200).send('No userId in meta — cannot credit');
      return;
    }

    await creditWalletForFlutterwaveTx({
      userId,
      txRef: verified.tx_ref,
      amount: verified.amount,
      flwRef: verified.flw_ref,
    });

    res.status(200).send('OK');
  } catch (e) {
    console.error('flutterwaveWebhook error:', e);
    res.status(200).send('Error logged'); // Still 200 — avoid endless retries on our own bugs.
  }
});

/**
 * Redirect target for Flutterwave's Standard/redirect checkout flow
 * (used as a fallback for 3D-Secure/OTP steps that can't complete
 * inside the inline iframe). Verifies the transaction, credits the
 * wallet if not already done, then bounces the browser back into
 * the app with a simple status flag.
 */
exports.flutterwaveCallback = functions.https.onRequest(async (req, res) => {
  const { transaction_id, tx_ref, status: fwStatus } = req.query;
  const appUrl = 'https://zmonie.com.ng/';

  if (fwStatus === 'cancelled' || !transaction_id) {
    res.redirect(`${appUrl}?fw_status=cancelled`);
    return;
  }

  try {
    const secrets = await getFlutterwaveSecrets();
    if (!secrets || !secrets.secretKey) {
      res.redirect(`${appUrl}?fw_status=error`);
      return;
    }
    const result = await flwVerifyByTransactionId(secrets.secretKey, transaction_id);
    const txData = result && result.data;
    if (!txData || result.status !== 'success' || txData.status !== 'successful') {
      res.redirect(`${appUrl}?fw_status=failed`);
      return;
    }
    const userId = txData.meta && txData.meta.userId;
    if (userId) {
      await creditWalletForFlutterwaveTx({
        userId,
        txRef: txData.tx_ref,
        amount: txData.amount,
        flwRef: txData.flw_ref,
      });
    }
    res.redirect(`${appUrl}?fw_status=success&tx_ref=${encodeURIComponent(tx_ref || '')}`);
  } catch (e) {
    console.error('flutterwaveCallback error:', e);
    res.redirect(`${appUrl}?fw_status=error`);
  }
});

/**
 * Admin-only: confirms a saved Secret Key actually authenticates
 * with Flutterwave, without needing a real transaction.
 */
exports.testFlutterwaveSecret = functions.https.onCall(async (data, context) => {
  if (!context.auth || (context.auth.token.email || '').toLowerCase() !== SUPER_ADMIN_EMAIL) {
    throw new functions.https.HttpsError(
      'permission-denied',
      'Only the Super Admin can test the Flutterwave secret key.'
    );
  }
  const secrets = await getFlutterwaveSecrets();
  if (!secrets || !secrets.secretKey) {
    return { valid: false, message: 'No Secret Key has been saved yet.' };
  }
  try {
    // Lightweight authenticated GET — succeeds only with a valid secret key.
    const res = await fetch(`${FLW_API}/banks/NG`, {
      headers: { Authorization: `Bearer ${secrets.secretKey}` },
    });
    if (res.status === 401 || res.status === 403) {
      return { valid: false, message: 'This Secret Key was rejected by Flutterwave. Double-check it.' };
    }
    const body = await res.json();
    if (body.status === 'success' || res.status === 200) {
      return { valid: true, message: 'Secret Key is valid and recognized by Flutterwave.' };
    }
    return { valid: false, message: body.message || 'Flutterwave rejected this key.' };
  } catch (e) {
    return { valid: false, message: 'Could not reach Flutterwave: ' + e.message };
  }
});
