/**
 * ZMONIE — Secure backend functions
 * Deploy with: firebase deploy --only functions
 *
 * Every wallet CREDIT in the whole app must happen here (Admin SDK),
 * never in client JS. The client only ever: (1) initiates a payment,
 * (2) sends the resulting reference here for verification.
 */
const functions = require('firebase-functions');
const admin = require('firebase-admin');
const fetch = require('node-fetch'); // npm i node-fetch@2 in functions/
admin.initializeApp();
const db = admin.firestore();

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
async function isAdmin(uid) {
  const doc = await db.collection('admins').doc(uid).get();
  return doc.exists;
}

async function getSecret(docId, field) {
  const snap = await db.collection('adminSettings').doc(docId).get();
  if (!snap.exists) return null;
  return snap.data()[field] || null;
}

/**
 * Atomically claims a payment reference so it can never be processed
 * twice, then credits the wallet + writes an immutable transaction
 * record, all in a single Firestore transaction.
 */
async function creditWalletOnce({ ref, userId, amount, source, description, extra = {} }) {
  const refDoc = db.collection('processedPayments').doc(ref);
  return db.runTransaction(async (tx) => {
    const existing = await tx.get(refDoc);
    if (existing.exists) {
      // Already processed — return the prior result, do NOT credit again.
      return { success: true, alreadyProcessed: true };
    }
    if (!(amount > 0)) throw new functions.https.HttpsError('invalid-argument', 'Invalid amount');

    const userRef = db.collection('users').doc(userId);
    const userSnap = await tx.get(userRef);
    if (!userSnap.exists) throw new functions.https.HttpsError('not-found', 'User not found');

    tx.set(refDoc, {
      userId, amount, source,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    tx.update(userRef, {
      balance: admin.firestore.FieldValue.increment(amount),
      hasFundedFirst: true,
    });
    const txRef = db.collection('transactions').doc();
    tx.set(txRef, {
      userId, type: 'credit', amount, description,
      status: 'success', ref, source,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      ...extra,
    });
    return { success: true, alreadyProcessed: false };
  });
}

// ---------------------------------------------------------------
// PAYSTACK — verify then credit (client never writes balance)
// ---------------------------------------------------------------
exports.verifyPaystackTransaction = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'Log in required');
  const uid = context.auth.uid;
  const { reference, expectedAmount } = data;
  if (!reference || typeof reference !== 'string') {
    throw new functions.https.HttpsError('invalid-argument', 'Missing reference');
  }
  if (!(expectedAmount > 0)) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid amount');
  }

  const secretKey = await getSecret('paystackSecrets', 'secretKey');
  if (!secretKey) throw new functions.https.HttpsError('failed-precondition', 'Paystack not configured');

  const resp = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${secretKey}` },
  });
  const json = await resp.json();

  if (!json.status || !json.data || json.data.status !== 'success') {
    return { success: false, reason: 'not_successful' };
  }
  // Paystack amounts are in kobo.
  const paidNaira = json.data.amount / 100;
  if (Math.abs(paidNaira - expectedAmount) > 0.5) {
    return { success: false, reason: 'amount_mismatch' };
  }
  if (json.data.metadata && json.data.metadata.userId && json.data.metadata.userId !== uid) {
    throw new functions.https.HttpsError('permission-denied', 'Reference belongs to another user');
  }

  const result = await creditWalletOnce({
    ref: `paystack_${reference}`,
    userId: uid,
    amount: paidNaira,
    source: 'paystack',
    description: `Wallet Funded via Paystack (Ref: ${reference})`,
  });

  await maybeCreditReferralBonus(uid);
  return result;
});

// ---------------------------------------------------------------
// FLUTTERWAVE — verify then credit
// ---------------------------------------------------------------
exports.verifyFlutterwaveTransaction = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'Log in required');
  const uid = context.auth.uid;
  const { transaction_id, tx_ref, expectedAmount } = data;
  if (!transaction_id) throw new functions.https.HttpsError('invalid-argument', 'Missing transaction_id');
  if (!(expectedAmount > 0)) throw new functions.https.HttpsError('invalid-argument', 'Invalid amount');

  const secretKey = await getSecret('flutterwaveSecrets', 'secretKey');
  if (!secretKey) throw new functions.https.HttpsError('failed-precondition', 'Flutterwave not configured');

  const resp = await fetch(`https://api.flutterwave.com/v3/transactions/${transaction_id}/verify`, {
    headers: { Authorization: `Bearer ${secretKey}` },
  });
  const json = await resp.json();

  if (json.status !== 'success' || !json.data || json.data.status !== 'successful') {
    return { success: false, reason: 'not_successful' };
  }
  if (json.data.amount < expectedAmount || json.data.currency !== 'NGN') {
    return { success: false, reason: 'amount_mismatch' };
  }
  if (json.data.meta && json.data.meta.userId && json.data.meta.userId !== uid) {
    throw new functions.https.HttpsError('permission-denied', 'Reference belongs to another user');
  }

  const result = await creditWalletOnce({
    ref: `flutterwave_${json.data.tx_ref || tx_ref}`,
    userId: uid,
    amount: json.data.amount,
    source: 'flutterwave',
    description: `Wallet Funded via Flutterwave (Ref: ${json.data.tx_ref || tx_ref})`,
  });

  await maybeCreditReferralBonus(uid);
  return result;
});

async function maybeCreditReferralBonus(uid) {
  const userSnap = await db.collection('users').doc(uid).get();
  const user = userSnap.data();
  if (!user || user.referralBonusPaid || !user.referredBy) return;
  const rSnap = await db.collection('settings').doc('rewards').get();
  const rCfg = rSnap.exists ? rSnap.data() : {};
  if (rCfg.referralEnabled === false) return;
  const rAmt = rCfg.referralAmt || 100;
  await db.runTransaction(async (tx) => {
    const freshUser = await tx.get(db.collection('users').doc(uid));
    if (freshUser.data().referralBonusPaid) return; // idempotency guard
    tx.update(db.collection('users').doc(uid), { referralBonusPaid: true });
    tx.update(db.collection('users').doc(user.referredBy), {
      balance: admin.firestore.FieldValue.increment(rAmt),
      referralEarned: admin.firestore.FieldValue.increment(rAmt),
    });
  });
}

// ---------------------------------------------------------------
// WEBHOOKS (defense in depth — in case the client never returns
// from checkout, e.g. app closed mid-payment)
// ---------------------------------------------------------------
exports.flutterwaveWebhook = functions.https.onRequest(async (req, res) => {
  const secretHash = await getSecret('flutterwaveStatus', 'webhookSecret');
  if (!secretHash || req.headers['verif-hash'] !== secretHash) {
    return res.status(401).send('Unauthorized');
  }
  const event = req.body;
  if (event.data && event.data.status === 'successful') {
    const userId = event.data.meta && event.data.meta.userId;
    if (userId) {
      await creditWalletOnce({
        ref: `flutterwave_${event.data.tx_ref}`,
        userId,
        amount: event.data.amount,
        source: 'flutterwave_webhook',
        description: `Wallet Funded via Flutterwave Webhook (Ref: ${event.data.tx_ref})`,
      });
    }
  }
  res.status(200).send('ok');
});

// ---------------------------------------------------------------
// ADMIN-ONLY CALLABLES — replace every ad hoc client-side
// db.collection('users').doc(x).update({balance: increment(...)})
// used in the admin panel with a call to one of these instead.
// ---------------------------------------------------------------
exports.adminApproveFunding = functions.https.onCall(async (data, context) => {
  if (!context.auth || !(await isAdmin(context.auth.uid))) {
    throw new functions.https.HttpsError('permission-denied', 'Admins only');
  }
  const { fundingId } = data;
  const fundRef = db.collection('fundingRequests').doc(fundingId);
  return db.runTransaction(async (tx) => {
    const snap = await tx.get(fundRef);
    if (!snap.exists) throw new functions.https.HttpsError('not-found', 'Request not found');
    const f = snap.data();
    if (f.status !== 'pending') throw new functions.https.HttpsError('failed-precondition', 'Already processed');
    if (!(f.amount > 0)) throw new functions.https.HttpsError('invalid-argument', 'Invalid amount');

    tx.update(fundRef, {
      status: 'approved',
      approvedAt: admin.firestore.FieldValue.serverTimestamp(),
      approvedBy: context.auth.uid,
    });
    tx.update(db.collection('users').doc(f.userId), {
      balance: admin.firestore.FieldValue.increment(f.amount),
    });
    tx.set(db.collection('transactions').doc(), {
      userId: f.userId, type: 'credit', amount: f.amount,
      description: 'Wallet Funding (Admin Approved)', status: 'success',
      approvedBy: context.auth.uid,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return { success: true };
  });
});

exports.adminApproveWithdrawal = functions.https.onCall(async (data, context) => {
  if (!context.auth || !(await isAdmin(context.auth.uid))) {
    throw new functions.https.HttpsError('permission-denied', 'Admins only');
  }
  const { withdrawalId } = data;
  const wRef = db.collection('withdrawalRequests').doc(withdrawalId);
  return db.runTransaction(async (tx) => {
    const snap = await tx.get(wRef);
    if (!snap.exists) throw new functions.https.HttpsError('not-found', 'Request not found');
    const w = snap.data();
    if (w.status !== 'pending') throw new functions.https.HttpsError('failed-precondition', 'Already processed');

    const userSnap = await tx.get(db.collection('users').doc(w.userId));
    const currentBalance = (userSnap.data() || {}).balance || 0;
    if (currentBalance < w.amount) throw new functions.https.HttpsError('failed-precondition', 'Insufficient balance');

    tx.update(wRef, {
      status: 'approved',
      approvedAt: admin.firestore.FieldValue.serverTimestamp(),
      approvedBy: context.auth.uid,
    });
    tx.update(db.collection('users').doc(w.userId), {
      balance: admin.firestore.FieldValue.increment(-w.amount),
    });
    tx.set(db.collection('transactions').doc(), {
      userId: w.userId, type: 'debit', amount: w.amount,
      description: 'Withdrawal (Admin Approved)', status: 'success',
      approvedBy: context.auth.uid,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return { success: true };
  });
});

// Generic admin wallet adjustment — replaces bulk/manual "Wallet Ops" in
// the admin panel. Every use is logged with the acting admin's uid.
exports.adminAdjustWallet = functions.https.onCall(async (data, context) => {
  if (!context.auth || !(await isAdmin(context.auth.uid))) {
    throw new functions.https.HttpsError('permission-denied', 'Admins only');
  }
  const { userId, amount, op, note } = data; // op: 'credit' | 'debit'
  if (!userId || !(amount > 0) || !['credit', 'debit'].includes(op)) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid input');
  }
  const delta = op === 'credit' ? amount : -amount;
  await db.collection('users').doc(userId).update({
    balance: admin.firestore.FieldValue.increment(delta),
  });
  await db.collection('transactions').add({
    userId, type: op, amount, description: note || `Admin ${op}`,
    status: 'success', adminId: context.auth.uid,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  return { success: true };
});

// Test that a Paystack/Flutterwave secret key is valid without exposing it.
exports.testFlutterwaveSecret = functions.https.onCall(async (data, context) => {
  if (!context.auth || !(await isAdmin(context.auth.uid))) {
    throw new functions.https.HttpsError('permission-denied', 'Admins only');
  }
  const secretKey = await getSecret('flutterwaveSecrets', 'secretKey');
  if (!secretKey) return { valid: false };
  const resp = await fetch('https://api.flutterwave.com/v3/transactions?page=1', {
    headers: { Authorization: `Bearer ${secretKey}` },
  });
  return { valid: resp.ok };
});
