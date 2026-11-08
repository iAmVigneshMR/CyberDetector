// CyberDetector — ClickFix / clipboard-hijack protection.
// Runs in the PAGE's JavaScript world (registered dynamically by the background only while
// "ClickFix protection" is enabled), because only there can a page's clipboard writes be seen.
//
// ClickFix pages show a fake CAPTCHA, silently copy a malicious command, and tell the user to
// press Win+R → Ctrl+V → Enter. We intercept every clipboard-write path and replace dangerous
// commands with a harmless warning before they ever reach the clipboard.
//
// Limitation: a page that specifically targets this extension can still obtain pristine
// clipboard functions (e.g. from a fresh iframe). This is defence in depth, not a guarantee.
(function (root) {
  'use strict';

  const SEVERE = [
    [/\b(powershell|pwsh)(\.exe)?\b[^\n]{0,400}?(\s-w(indowstyle)?\s+(h|hidden|1)\b|\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{16,}|\biex\b|invoke-expression|\biwr\b|invoke-webrequest|downloadstring|downloadfile|frombase64string|start-bitstransfer|\birm\b)/i, 'Hidden / download-and-run PowerShell'],
    [/\bmshta(\.exe)?\s+["']?(https?:|vbscript:|javascript:|\\\\)/i, 'mshta running remote script'],
    [/\b(iex|invoke-expression)\s*[(\s]/i, 'PowerShell Invoke-Expression'],
    [/\bcertutil(\.exe)?\b[^\n]*-urlcache/i, 'certutil download'],
    [/\bbitsadmin(\.exe)?\b[^\n]*\/transfer/i, 'bitsadmin download'],
    [/\brundll32(\.exe)?\b[^\n]*(javascript:|https?:|\\\\)/i, 'rundll32 loading remote code'],
    [/\bregsvr32(\.exe)?\b[^\n]*\/i:\s*https?:/i, 'regsvr32 remote scriptlet'],
    [/\bmsiexec(\.exe)?\b[^\n]*\/(i|package)\s+["']?https?:/i, 'msiexec installing from the internet'],
    [/\bconhost(\.exe)?\s+--headless/i, 'Hidden console window'],
    [/\bcmd(\.exe)?\s+\/[ck]\b[^\n]*(curl|powershell|pwsh|mshta|bitsadmin|certutil|start\s+\/min|\bnet\s+use\b)/i, 'cmd chaining a downloader'],
    [/\bnslookup\b[^\n]*\|[^\n]*(cmd|powershell|pwsh|findstr)/i, 'DNS-lookup payload piped into a shell'],
    [/\bnet\s+use\s+[a-z]:?\s*\\\\/i, 'Mapping a remote network share'],
    [/\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b[^\n]*#/i, 'curl | sh with a disguising comment'],
    [/\bbase64\s+(-d|--decode|-D)\b[^\n]*\|\s*(sudo\s+)?(ba|z)?sh\b/i, 'Decoding and running hidden shell code'],
    [/\bosascript\s+-e\b[^\n]*(do shell script|curl)/i, 'AppleScript running shell commands'],
    [/^[^\n#]{8,}#[^\n]*(robot|human|captcha|verif|cloudflare|recaptcha|✅|✔)/i, 'Command disguised with a fake "verification" comment'],
  ];
  const COMMAND = /^\s*(powershell|pwsh|cmd(\.exe)?\s|bash|sh\s|zsh|curl\s|wget\s|sudo\s|chmod\s|osascript|python3?\s+-c|node\s+-e|msiexec|rundll32|regsvr32|wscript|cscript|mshta|start\s|explorer\s|iex|\$\w+\s*=)/i;
  const LURE = /(win(dows)?\s*(key|logo key)?\s*\+\s*r\b|⊞\s*\+?\s*r\b|press\s+(the\s+)?windows\s+(key|button)|ctrl\s*\+\s*v|cmd\s*\+\s*v|⌘\s*\+?\s*v|run dialog|verify you are (a )?human|i('| a)m not a robot|verification steps|complete (the )?verification|press enter to (verify|complete))/i;

  function classify(text) {
    const t = String(text || '').slice(0, 20000);
    for (const [re, reason] of SEVERE) if (re.test(t)) return { level: 'severe', reason };
    if (COMMAND.test(t) || /\|\s*(iex|sh|bash)\b/i.test(t)) return { level: 'command', reason: 'Terminal command' };
    return { level: 'none' };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { classify, LURE };
    return;
  }

  const warnAny = !!root.__cyberdetectorClipboardWarnAny;
  try { delete root.__cyberdetectorClipboardWarnAny; } catch { /* ignore */ }
  const SAFE_TEXT = '⚠ CyberDetector blocked a command this website tried to copy to your clipboard. Never paste text a website tells you to run in Win+R, Terminal or PowerShell.';

  function pageHasLure() {
    try {
      return LURE.test((document.body?.innerText || '').slice(0, 60000));
    } catch {
      return false;
    }
  }

  function report(action, text, reason) {
    root.dispatchEvent(new CustomEvent('cyberdetector:clipboard', {
      detail: JSON.stringify({ action, reason, text: String(text).slice(0, 600), url: location.href }),
    }));
  }

  /** Returns the text that should actually reach the clipboard. */
  function decide(text) {
    const c = classify(text);
    if (c.level === 'none') return text;
    if (c.level === 'severe' || pageHasLure()) {
      report('blocked', text, c.level === 'severe' ? c.reason : `${c.reason} on a page with "paste and run" instructions`);
      return SAFE_TEXT;
    }
    if (warnAny) report('warned', text, c.reason);
    return text;
  }

  const ClipboardProto = root.Clipboard && root.Clipboard.prototype;
  if (ClipboardProto && ClipboardProto.writeText) {
    const origWriteText = ClipboardProto.writeText;
    ClipboardProto.writeText = function (text) {
      return origWriteText.call(this, decide(text));
    };
    if (ClipboardProto.write && root.ClipboardItem) {
      const origWrite = ClipboardProto.write;
      ClipboardProto.write = async function (items) {
        try {
          for (const item of items || []) {
            if (item.types && item.types.includes('text/plain')) {
              const text = await (await item.getType('text/plain')).text();
              const safe = decide(text);
              if (safe !== text) return origWriteText.call(this, safe);
            }
          }
        } catch { /* fall through to original */ }
        return origWrite.call(this, items);
      };
    }
  }

  const DT = root.DataTransfer && root.DataTransfer.prototype;
  const origSetData = DT && DT.setData;
  if (origSetData) {
    DT.setData = function (type, data) {
      if (/^text(\/plain)?$/i.test(String(type))) data = decide(data);
      return origSetData.call(this, type, data);
    };
  }

  const DocProto = root.Document && root.Document.prototype;
  const origExec = DocProto && DocProto.execCommand;
  if (origExec) {
    DocProto.execCommand = function (cmd, ...rest) {
      if (/^(copy|cut)$/i.test(String(cmd))) {
        let selected = '';
        try {
          const a = document.activeElement;
          selected = a && typeof a.value === 'string' && a.selectionEnd > a.selectionStart
            ? a.value.slice(a.selectionStart, a.selectionEnd)
            : String(root.getSelection ? root.getSelection() : '');
        } catch { /* ignore */ }
        const safe = decide(selected);
        if (safe !== selected) {
          // Copy the safe text instead, using the ORIGINAL functions (no re-entry into our hooks).
          const swap = (e) => {
            e.stopImmediatePropagation();
            e.preventDefault();
            if (e.clipboardData && origSetData) origSetData.call(e.clipboardData, 'text/plain', safe);
          };
          document.addEventListener('copy', swap, { capture: true, once: true });
          document.addEventListener('cut', swap, { capture: true, once: true });
          try {
            return origExec.call(this, cmd, ...rest);
          } finally {
            document.removeEventListener('copy', swap, { capture: true });
            document.removeEventListener('cut', swap, { capture: true });
          }
        }
      }
      return origExec.call(this, cmd, ...rest);
    };
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
