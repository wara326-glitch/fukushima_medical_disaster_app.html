# Firebase secure backend migration

Branch: firebase-secure-backend

## Security boundary
- Public GitHub Pages: anyone can submit.
- Public browser: cannot read/update/delete Firestore.
- Submission: HTTPS Cloud Function using Admin SDK.
- Admin: Google Sign-In; Firestore rules require an enabled admin_profiles/{uid}.
- Roles: viewer (read), editor (read/update), admin (read/update/delete + profiles/audit).
- No service-account key is committed to GitHub.

## Setup
1. Create a Firebase project and Web app.
2. Enable Authentication > Google.
3. Add wara326-glitch.github.io to Authentication > Settings > Authorized domains.
4. Create Firestore in a Japan/appropriate region.
5. Install Firebase CLI locally, login, and set project in .firebaserc.
6. Deploy: firebase deploy --only functions,firestore:rules
7. Copy Firebase Web config into firebase-config.js and the deployed submitReport URL into FMA_SUBMIT_URL.
8. Deploy the branch to a test Pages environment before merging to main.
9. Sign in once with the intended administrator Google account, obtain its Firebase Auth UID in Firebase Console, then create:
   admin_profiles/{UID} = { enabled: true, role: "admin", email: "ADMIN_EMAIL" }
10. Test anonymous submit, anonymous read denial, unauthorized Google account denial, viewer/editor/admin permissions.

## Important
Do not put service-account JSON, private keys, passwords, recovery codes, or patient-identifying data in this repository.
