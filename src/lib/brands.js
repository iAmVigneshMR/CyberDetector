// Brands most frequently impersonated in phishing campaigns.
//   keywords: lowercase ASCII labels used for typosquat / combosquat comparison
//   domains:  official registrable domains (exact match => legitimate)
//   mentions: names searched for in page titles / login forms (brand impersonation)
export const BRANDS = [
  { name: 'PayPal', keywords: ['paypal'], domains: ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal-community.com'] },
  {
    name: 'Google',
    keywords: ['google', 'gmail', 'youtube'],
    mentions: ['Google', 'Gmail'],
    domains: ['google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.ca', 'google.com.au', 'gmail.com', 'youtube.com', 'youtu.be', 'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'withgoogle.com', 'goo.gl', 'g.co', 'forms.gle', 'blogger.com', 'android.com', 'chrome.com'],
  },
  {
    name: 'Microsoft',
    keywords: ['microsoft', 'outlook', 'office365', 'onedrive', 'sharepoint', 'hotmail', 'microsoftonline'],
    mentions: ['Microsoft', 'Outlook', 'Office 365', 'Microsoft 365', 'OneDrive', 'SharePoint'],
    domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com', 'sharepoint.com', 'onedrive.com', 'hotmail.com', 'msn.com', 'bing.com', 'azure.com', 'windows.net', 'windows.com', 'xbox.com', 'skype.com', '1drv.ms', 'aka.ms', 'microsoft365.com', 'cloud.microsoft', 'msauth.net', 'msftauth.net'],
  },
  { name: 'Apple', keywords: ['apple', 'icloud', 'itunes'], mentions: ['Apple ID', 'iCloud', 'Apple'], domains: ['apple.com', 'icloud.com', 'me.com', 'apple.co', 'itunes.com', 'mzstatic.com'] },
  {
    name: 'Amazon',
    keywords: ['amazon'],
    domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.co.jp', 'amazon.com.au', 'amazonaws.com', 'amzn.to', 'a.co', 'primevideo.com', 'amazon.ae', 'amazon.sa'],
  },
  { name: 'Facebook', keywords: ['facebook'], domains: ['facebook.com', 'fb.com', 'fb.me', 'messenger.com', 'fbcdn.net', 'meta.com'] },
  { name: 'Instagram', keywords: ['instagram'], domains: ['instagram.com', 'cdninstagram.com'] },
  { name: 'WhatsApp', keywords: ['whatsapp'], domains: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
  { name: 'Netflix', keywords: ['netflix'], domains: ['netflix.com', 'nflxext.com', 'nflximg.net'] },
  { name: 'LinkedIn', keywords: ['linkedin'], domains: ['linkedin.com', 'lnkd.in', 'licdn.com'] },
  { name: 'Twitter / X', keywords: ['twitter'], mentions: ['Twitter'], domains: ['twitter.com', 'x.com', 't.co', 'twimg.com'] },
  { name: 'Dropbox', keywords: ['dropbox'], domains: ['dropbox.com', 'dropboxusercontent.com', 'db.tt'] },
  { name: 'DocuSign', keywords: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
  { name: 'Adobe', keywords: ['adobe'], domains: ['adobe.com', 'adobelogin.com', 'adobesign.com', 'acrobat.com', 'adobe.io'] },
  { name: 'eBay', keywords: ['ebay'], domains: ['ebay.com', 'ebay.co.uk', 'ebay.de', 'ebay.in', 'ebayimg.com'] },
  { name: 'Coinbase', keywords: ['coinbase'], domains: ['coinbase.com'] },
  { name: 'Binance', keywords: ['binance'], domains: ['binance.com', 'binance.us'] },
  { name: 'MetaMask', keywords: ['metamask'], domains: ['metamask.io'] },
  { name: 'Ledger', keywords: ['ledger'], mentions: ['Ledger Live'], domains: ['ledger.com'] },
  { name: 'Trust Wallet', keywords: ['trustwallet'], domains: ['trustwallet.com'] },
  { name: 'Kraken', keywords: ['kraken'], domains: ['kraken.com'] },
  { name: 'Steam', keywords: ['steampowered', 'steamcommunity'], mentions: ['Steam'], domains: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com'] },
  { name: 'Yahoo', keywords: ['yahoo'], domains: ['yahoo.com', 'yahoo.co.jp', 'yimg.com'] },
  { name: 'GitHub', keywords: ['github'], domains: ['github.com', 'githubusercontent.com', 'githubassets.com', 'github.blog', 'github.dev'] },
  { name: 'Chase', keywords: ['chase'], mentions: ['Chase Bank', 'JPMorgan Chase'], domains: ['chase.com', 'jpmorganchase.com'] },
  { name: 'Bank of America', keywords: ['bankofamerica'], domains: ['bankofamerica.com', 'bofa.com'] },
  { name: 'Wells Fargo', keywords: ['wellsfargo'], domains: ['wellsfargo.com'] },
  { name: 'Citibank', keywords: ['citibank'], mentions: ['Citibank'], domains: ['citi.com', 'citibank.com'] },
  { name: 'HSBC', keywords: ['hsbc'], domains: ['hsbc.com', 'hsbc.co.uk', 'hsbc.co.in'] },
  { name: 'American Express', keywords: ['americanexpress', 'amex'], domains: ['americanexpress.com', 'aexp.com'] },
  { name: 'Capital One', keywords: ['capitalone'], domains: ['capitalone.com'] },
  { name: 'Venmo', keywords: ['venmo'], domains: ['venmo.com'] },
  { name: 'Cash App', keywords: ['cashapp'], domains: ['cash.app', 'cash.me', 'squareup.com'] },
  { name: 'USPS', keywords: ['usps'], domains: ['usps.com'] },
  { name: 'UPS', keywords: ['ups'], mentions: [], domains: ['ups.com'] },
  { name: 'FedEx', keywords: ['fedex'], domains: ['fedex.com'] },
  { name: 'DHL', keywords: ['dhl'], domains: ['dhl.com', 'dhl.de'] },
  { name: 'IRS', keywords: ['irs'], mentions: ['Internal Revenue Service'], domains: ['irs.gov'] },
  { name: 'State Bank of India', keywords: ['onlinesbi', 'sbi'], mentions: ['State Bank of India', 'SBI'], domains: ['onlinesbi.sbi', 'sbi.co.in', 'onlinesbi.com', 'sbi.bank.in'] },
  { name: 'HDFC Bank', keywords: ['hdfcbank', 'hdfc'], domains: ['hdfcbank.com', 'hdfc.com', 'hdfcbank.bank.in'] },
  { name: 'ICICI Bank', keywords: ['icicibank', 'icici'], domains: ['icicibank.com', 'icici.bank.in'] },
  { name: 'Axis Bank', keywords: ['axisbank'], domains: ['axisbank.com', 'axis.bank.in'] },
  { name: 'Kotak', keywords: ['kotak'], domains: ['kotak.com', 'kotak.bank.in'] },
  { name: 'Paytm', keywords: ['paytm'], domains: ['paytm.com', 'paytm.in'] },
  { name: 'PhonePe', keywords: ['phonepe'], domains: ['phonepe.com'] },
  { name: 'Flipkart', keywords: ['flipkart'], domains: ['flipkart.com'] },
  { name: 'IRCTC', keywords: ['irctc'], domains: ['irctc.co.in'] },
  { name: 'Aadhaar / UIDAI', keywords: ['uidai', 'aadhaar'], mentions: ['UIDAI', 'Aadhaar'], domains: ['uidai.gov.in', 'myaadhaar.uidai.gov.in'] },
  { name: 'Income Tax India', keywords: ['incometax'], mentions: ['Income Tax Department'], domains: ['incometax.gov.in'] },
  { name: 'Zoom', keywords: ['zoom'], mentions: [], domains: ['zoom.us', 'zoom.com'] },
  { name: 'Spotify', keywords: ['spotify'], domains: ['spotify.com', 'scdn.co'] },
  { name: 'Discord', keywords: ['discord'], domains: ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net'] },
  { name: 'Telegram', keywords: ['telegram'], domains: ['telegram.org', 't.me', 'telegram.me'] },
  { name: 'Roblox', keywords: ['roblox'], domains: ['roblox.com', 'rbxcdn.com'] },
  { name: 'Epic Games', keywords: ['epicgames'], domains: ['epicgames.com', 'unrealengine.com'] },
  { name: 'Okta', keywords: ['okta'], domains: ['okta.com', 'oktacdn.com', 'okta-emea.com'] },
  { name: 'Salesforce', keywords: ['salesforce'], domains: ['salesforce.com', 'force.com'] },
  { name: 'Walmart', keywords: ['walmart'], domains: ['walmart.com'] },
  { name: 'WeTransfer', keywords: ['wetransfer'], domains: ['wetransfer.com', 'we.tl'] },
];

/** Every official domain → brand, for O(1) lookup. */
export const OFFICIAL_DOMAINS = new Map();
for (const b of BRANDS) for (const d of b.domains) OFFICIAL_DOMAINS.set(d, b);

/**
 * Return the brand that officially owns `host` (exact or subdomain of an
 * official domain), or null.
 */
export function officialBrandFor(host) {
  for (const [d, brand] of OFFICIAL_DOMAINS) {
    if (host === d || host.endsWith('.' + d)) return brand;
  }
  return null;
}

export function brandMentions(brand) {
  if (brand.mentions) return brand.mentions;
  return brand.name.length >= 4 ? [brand.name] : [];
}
