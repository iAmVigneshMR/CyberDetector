// Risky-download guard. Pauses a download and asks the user when a dangerous file type
// comes with a second red flag (flagged page, HTML smuggling, disguised extension).
// Normal installer downloads from normal sites are left alone.

const EXEC = /\.(exe|scr|com|pif|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|msi|msix|msixbundle|appx|lnk|url|iso|img|vhd|vhdx|jar|cpl|reg|chm|xll|one|dll|application|appref-ms|sh|command|app|pkg|dmg|apk)$/i;
const ARCHIVE = /\.(zip|rar|7z|tar|gz|tgz|cab|ace)$/i;
const SCRIPTY_HTML = /\.(html?|shtml|svg|xht(ml)?)$/i;
const DOUBLE_EXT = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|mp4|mp3|zip)[\s._-]*\.(exe|scr|js|jse|hta|vbs|vbe|cmd|bat|lnk|html?|com|pif|msi)$/i;
const RLO = /‮/; // right-to-left override used to fake extensions ("invoice‮fdp.exe")

/**
 * @param {{filename: string, url: string, finalUrl?: string, mime?: string}} item
 * @param {{level?: string, reason?: string}|null} pageVerdict verdict of the tab that started the download
 * @returns {{risky: boolean, severity: 'high'|'medium'|null, reasons: string[]}}
 */
export function assessDownload(item, pageVerdict) {
  const name = (item.filename || '').split(/[\\/]/).pop() || '';
  const url = item.finalUrl || item.url || '';
  const reasons = [];
  const exec = EXEC.test(name);
  const archive = ARCHIVE.test(name);
  const html = SCRIPTY_HTML.test(name);
  const smuggled = /^(blob|data):/i.test(url);
  const flagged = pageVerdict && (pageVerdict.level === 'danger' || pageVerdict.level === 'warning');

  if (RLO.test(name)) reasons.push('The file name uses a hidden right-to-left character to fake its extension');
  if (DOUBLE_EXT.test(name)) reasons.push(`Disguised file type: "${name}" looks like a document but is ${name.split('.').pop().toUpperCase()}`);
  if (smuggled && (exec || archive || html)) reasons.push('The file was assembled inside the web page ("HTML smuggling") — a common way to sneak malware past filters');
  if (flagged && (exec || archive || html)) reasons.push(`It comes from a page CyberDetector flagged (${pageVerdict.level}: ${pageVerdict.reason})`);
  if (html && /\.(svg|html?)$/i.test(name) && smuggled) reasons.push('Downloaded web pages/SVGs are often fake login pages that run locally');

  const severity = reasons.length === 0 ? null : RLO.test(name) || DOUBLE_EXT.test(name) || (smuggled && exec) || (flagged && pageVerdict.level === 'danger') ? 'high' : 'medium';
  return { risky: reasons.length > 0, severity, reasons, name, exec };
}
