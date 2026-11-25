// Reports names that are used but not declared (TS2304/TS2552) and wrong arity/obvious misuse in the page source, with TypeScript's checker.
const ts = require('/home/woowtechopenclaw/Woow_cloudflare_tunnel_webgui/frontend/node_modules/typescript');
const file = process.argv[2];
const program = ts.createProgram([file], { allowJs: true, checkJs: true, noEmit: true, target: ts.ScriptTarget.ES2022, lib: ['lib.es2022.d.ts', 'lib.dom.d.ts'],
  skipLibCheck: true, strict: false, noImplicitAny: false, types: [] });
const wanted = new Set([2304, 2552, 2448, 2454, 2451, 2349, 2554]);   // not found, did you mean, used before declaration, not assigned, redeclare, not callable, wrong arg count
let count = 0;
for (const d of ts.getPreEmitDiagnostics(program)) {
  if (!d.file || !d.file.fileName.endsWith(file.split('/').pop()) || !wanted.has(d.code)) continue;
  const { line, character } = d.file.getLineAndCharacterOfPosition(d.start);
  console.log(`${d.file.fileName.split('/').pop()}:${line + 1}:${character + 1} TS${d.code} ${ts.flattenDiagnosticMessageText(d.messageText, ' ').slice(0, 160)}`);
  count += 1;
}
console.log(`${count} findings`);
