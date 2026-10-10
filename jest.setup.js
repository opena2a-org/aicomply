// Force the nanomind adapter to a known-bad URL so tests never accidentally
// hit a real local nanomind-daemon if a developer happens to be running one.
// Tests that want adapter success spin up their own mock server and pass its
// URL via the adapter's baseUrl option (which takes precedence over the env
// var). A test that reached a live daemon would give different results on
// different machines.
process.env.MOCK_NANOMIND_URL = 'http://127.0.0.1:1';
