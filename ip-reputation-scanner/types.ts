export enum ApiName {
  VIRUSTOTAL = 'VirusTotal',
  ABUSEIPDB = 'AbuseIPDB',
  SCAMALYTICS = 'Scamalytics',
}

export enum Severity {
  CLEAN = 'Clean',
  SUSPICIOUS = 'Suspicious',
  MALICIOUS = 'Malicious',
  UNKNOWN = 'Unknown',
  INFO = 'Informational'
}

export interface ApiKeyConfig {
  id: string;
  key: string;
  label?: string;
  addedDate: number;
}

export type ApiKeyStore = Partial<Record<ApiName, ApiKeyConfig[]>>;

// --- Detailed Service-Specific Data Structures ---
export interface VirusTotalVendorDetail {
  vendorName: string;
  result: 'Malicious' | 'Clean' | 'Unrated' | 'Suspicious';
  category?: string; // e.g., 'Phishing', 'Malware'
}

export interface VirusTotalSpecificData {
  detectionRatio?: string; // e.g., "10/94"
  communityScore?: number;
  asOwner?: string;
  vendorDetails?: VirusTotalVendorDetail[];
  lastAnalysisDate?: string; // Already present, but ensure it's populated
  country?: string; // Already present
}

export interface AbuseIPDBSpecificData {
  isp?: string; // Already present
  usageType?: string; // Already present
  domainName?: string;
  city?: string;
  totalReports?: number;
  isWhitelisted?: boolean;
  lastReportedAt?: string;
  countryCode?: string; // Already present as 'country'
}

export interface ScamalyticsOperatorDetails {
  asn?: string;
  ispName?: string;
  orgName?: string;
  connectionType?: string;
}

export interface ScamalyticsLocationDetails {
  countryName?: string; // Already present as 'country'
  countryCode?: string;
  state?: string;
  city?: string;
  postalCode?: string;
  latitude?: number;
  longitude?: number;
}

export interface ScamalyticsDatacenterInfo {
  isDatacenter: boolean | 'Unknown';
}

export interface ScamalyticsExternalBlacklistInfo {
  name: string;
  isListed: boolean;
}

export interface ScamalyticsProxyDetails {
  isVpn: boolean;
  isTor: boolean;
  isPublicProxy: boolean;
  isWebProxy: boolean;
  isSearchEngineRobot: boolean;
  isServer: boolean; // Indicates a non-residential server
}

export interface ScamalyticsSpecificData {
  fraudScore?: number; // Already present as 'score'
  riskLevel?: 'low' | 'medium' | 'high' | 'very_high' | 'unknown'; // Already somewhat as threatClassification
  riskDescription?: string;
  operatorDetails?: ScamalyticsOperatorDetails;
  locationDetails?: ScamalyticsLocationDetails;
  datacenterInfo?: ScamalyticsDatacenterInfo;
  externalBlacklists?: ScamalyticsExternalBlacklistInfo[];
  proxyDetails?: ScamalyticsProxyDetails;
  isBlacklistedExternal?: boolean; // General flag from some Scamalytics output
}


export interface ServiceScanResult {
  serviceName: ApiName;
  ip: string;
  status: 'success' | 'error' | 'rate_limited' | 'pending' | 'key_missing' | 'skipped' | 'not_found';
  data?: any; // Raw data from API (can be typed further if needed)
  summary?: string;
  score?: number; 
  severity?: Severity;
  detailsUrl?: string;
  errorMessage?: string;
  skippedReason?: string; 

  // Common detailed fields (some might be duplicated in specific data for clarity)
  country?: string;
  isp?: string; // Common but also in AbuseIPDB specific
  lastAnalysisDate?: string; // Common field

  // Service-specific structured data
  virusTotalSpecific?: VirusTotalSpecificData;
  abuseIpdbSpecific?: AbuseIPDBSpecificData;
  scamalyticsSpecific?: ScamalyticsSpecificData;

  // Legacy/Simplified fields that might be replaced by specific data
  usageType?: string; 
  domain?: string; 
  detectionRate?: string; 
  threatClassification?: string; 

  usedApiKeyId?: string;
}

export interface AggregatedScanResult {
  id: string; // Unique ID for the scan job
  ip: string;
  results: ServiceScanResult[];
  overallSeverity: Severity;
  isScanning: boolean;
  error?: string;
}

export enum AppTab {
  IP_SCANNER = 'ipScanner',
  API_KEYS = 'apiKeys',
}

export interface RateLimitConfig {
  requests: number;
  periodMilliseconds: number;
  dailyQuota?: number; // Optional: max requests per day
}

// For ipScanCoordinator rate limit tracking
export interface ApiKeyUsage {
  minuteTimestamps: number[];
  dailyCounts: { [dateISOString: string]: number }; // Key: "YYYY-MM-DD", Value: count
}

export enum ScanMode {
  FULL = 'full', // Scans all services
  SMART = 'smart' // Skips third service if first two are suspicious/malicious
}

export enum IpInputMode {
  FILE_UPLOAD = 'file_upload',
  MANUAL_ENTRY = 'manual_entry'
}