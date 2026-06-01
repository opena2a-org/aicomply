// Force the nanomind adapter to a known-bad URL so tests never accidentally
// hit a real local nanomind-daemon if a developer happens to be running one.
// Tests that want adapter success spin up their own mock server and pass its
// URL via the adapter's baseUrl option (which takes precedence over the env
// var). See feedback memory on environment-leaks-across-tests.
process.env.MOCK_NANOMIND_URL = 'http://127.0.0.1:1';
