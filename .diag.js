console.log('DNS:', (() => { try { return require('dns').sync ?? 'n/a'; } catch { return 'n/a'; } })());
const dns = require('node:dns');
dns.lookup('keycloak', (err, addr) => {
  console.log('DNS keycloak ->', err ? ('ERR ' + err.code) : addr);
  if (err) process.exit(0);
  fetch('https://keycloak:8443/health/live')
    .then(r => r.text().then(t => console.log('FETCH OK', r.status, t.slice(0, 80))))
    .catch(e => console.log('FETCH ERR', e.cause?.code || e.message));
});
