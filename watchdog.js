// WATCHDOG: keeps the service alive. If it dies, start it again after 1.5 seconds.
const { spawn } = require('child_process'), path = require('path');
let stopping = false;
process.on('SIGINT', () => { stopping = true; }); // Ctrl+C = clean stop, do not restart

function start() {
  const child = spawn(process.execPath, [path.join(__dirname, 'server.js')], { stdio: 'inherit' });
  child.on('exit', (code, signal) => {
    if (stopping || code === 0) return process.exit(0);
    console.log(`\n[watchdog] service died (${signal || 'code ' + code}). Restarting in 1.5s...\n`);
    setTimeout(start, 1500);
  });
}
start();
