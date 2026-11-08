import { ext, send } from '../lib/ext.js';

const q = new URLSearchParams(location.search);
const id = Number(q.get('id'));
const $ = (s) => document.querySelector(s);
let info = {};
try { info = JSON.parse(q.get('info') || '{}'); } catch { /* ignore */ }

$('#file').textContent = info.name || `Download #${id}`;
for (const r of info.reasons || []) {
  const li = document.createElement('li');
  li.textContent = r;
  $('#reasons').append(li);
}
$('#src').textContent = info.url ? `From: ${info.url.slice(0, 200)}` : '';
if (info.finished) {
  document.querySelector('h1').textContent = '⚠ CyberDetector flagged a risky download';
  $('#delete').textContent = 'Delete the file (recommended)';
  $('#keep').textContent = 'Keep the file';
}

const done = (text) => {
  $('#status').textContent = text;
  document.querySelectorAll('button').forEach((b) => { b.disabled = true; });
  setTimeout(() => window.close(), 1500);
};
$('#delete').addEventListener('click', async () => {
  try { await send({ type: 'downloadDecision', id, keep: false }); done('✓ Download deleted.'); } catch (e) { $('#status').textContent = e.message; }
});
$('#keep').addEventListener('click', async () => {
  if (!confirm('Only keep this file if you know and trust its sender. Continue?')) return;
  try { await send({ type: 'downloadDecision', id, keep: true }); done('Download resumed.'); } catch (e) { $('#status').textContent = e.message; }
});
void ext;
