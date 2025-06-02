import { ApiName, Severity, RateLimitConfig } from './types';

export const API_BASE_URLS: Record<ApiName, string> = {
  [ApiName.VIRUSTOTAL]: 'https://www.virustotal.com/api/v3/ip_addresses/',
  [ApiName.ABUSEIPDB]: 'https://api.abuseipdb.com/api/v2/check',
  [ApiName.SCAMALYTICS]: 'https://api.scamalytics.com/ip/', // Note: Scamalytics API structure might vary
};

// Updated Rate Limits
export const API_RATE_LIMITS: Record<ApiName, RateLimitConfig> = {
  [ApiName.VIRUSTOTAL]: { requests: 4, periodMilliseconds: 60000, dailyQuota: 500 },
  [ApiName.ABUSEIPDB]: { requests: 20, periodMilliseconds: 60000, dailyQuota: 1000 }, // Generous per minute, strict daily
  [ApiName.SCAMALYTICS]: { requests: 4, periodMilliseconds: 60000, dailyQuota: 150 }, // Derived from 5000/month
};

export const SEVERITY_COLORS: Record<Severity | 'SKIPPED', { text: string; bg: string; border: string; iconBg?: string, hoverBg?: string }> = {
  [Severity.CLEAN]: { text: 'text-green-700', bg: 'bg-green-100', border: 'border-green-400', iconBg: 'bg-green-500', hoverBg: 'hover:bg-green-200' },
  [Severity.INFO]: { text: 'text-sky-700', bg: 'bg-sky-100', border: 'border-sky-400', iconBg: 'bg-sky-500', hoverBg: 'hover:bg-sky-200' },
  [Severity.SUSPICIOUS]: { text: 'text-yellow-700', bg: 'bg-yellow-100', border: 'border-yellow-400', iconBg: 'bg-yellow-500', hoverBg: 'hover:bg-yellow-200' },
  [Severity.MALICIOUS]: { text: 'text-red-700', bg: 'bg-red-100', border: 'border-red-400', iconBg: 'bg-red-500', hoverBg: 'hover:bg-red-200' },
  [Severity.UNKNOWN]: { text: 'text-gray-700', bg: 'bg-gray-100', border: 'border-gray-400', iconBg: 'bg-gray-500', hoverBg: 'hover:bg-gray-200' },
  ['SKIPPED']: { text: 'text-slate-500', bg: 'bg-slate-200', border: 'border-slate-400', iconBg: 'bg-slate-400', hoverBg: 'hover:bg-slate-300' },
};


export const LOCAL_STORAGE_API_KEY_PREFIX = 'ipScannerApiKey_';
export const LOCAL_STORAGE_RATE_LIMIT_STATE_PREFIX = 'ipScannerRateLimitState_';
export const LOCAL_STORAGE_SCAN_HISTORY_KEY = 'ipScannerScanHistory';

// Order of services for smart scan decision making
export const SMART_SCAN_PRIMARY_SERVICES: ApiName[] = [ApiName.VIRUSTOTAL, ApiName.ABUSEIPDB];
export const SMART_SCAN_SECONDARY_SERVICE: ApiName = ApiName.SCAMALYTICS;
