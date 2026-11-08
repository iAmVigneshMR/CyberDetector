// Cross-browser API handle. Firefox exposes the promise-based `browser`
// namespace; Chrome MV3's `chrome` namespace is promise-based too.
export const ext = globalThis.browser ?? globalThis.chrome;

export const isFirefox = typeof globalThis.browser?.runtime?.getBrowserInfo === 'function';

/** Send a message to the background and unwrap the {ok, data, error} envelope. */
export async function send(message) {
  const res = await ext.runtime.sendMessage(message);
  if (!res) throw new Error('No response from background');
  if (!res.ok) throw new Error(res.error || 'Unknown error');
  return res.data;
}

export function withTimeout(ms) {
  return AbortSignal.timeout(ms);
}

/**
 * Firefox data-collection consent (Firefox 140+). Categories:
 *   browsingActivity — URLs sent to reputation services (Safe Browsing, PhishTank, crt.sh)
 *   websiteContent   — media sent to AI-detection APIs
 * Other browsers have no such API, so consent is implied by the user's settings.
 */
export async function hasDataConsent(category) {
  if (!isFirefox) return true;
  try {
    return await ext.permissions.contains({ data_collection: [category] });
  } catch {
    return true; // older Firefox without data_collection support
  }
}

/** Must be called from a user gesture. Resolves true if granted (or not applicable). */
export async function requestDataConsent(category) {
  if (!isFirefox) return true;
  try {
    if (await ext.permissions.contains({ data_collection: [category] })) return true;
    return await ext.permissions.request({ data_collection: [category] });
  } catch {
    return true;
  }
}
