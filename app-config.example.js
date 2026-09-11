// Copy to app-config.js when the Supabase project is provisioned.
// The values below are public client configuration only.
// NEVER place SUPABASE_SERVICE_ROLE_KEY or other secrets in GitHub Pages.
window.FMA_APP_CONFIG = {
  supabaseUrl: "https://YOUR_PROJECT_REF.supabase.co",
  supabasePublishableKey: "YOUR_PUBLIC_ANON_OR_PUBLISHABLE_KEY",
  submitReportUrl: "https://YOUR_PROJECT_REF.supabase.co/functions/v1/submit-report"
};
