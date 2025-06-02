import { ApiName, ServiceScanResult, ApiKeyStore, Severity, AggregatedScanResult, ApiKeyConfig, ApiKeyUsage, ScanMode } from '../types';
import { API_RATE_LIMITS, LOCAL_STORAGE_RATE_LIMIT_STATE_PREFIX, SMART_SCAN_PRIMARY_SERVICES, SMART_SCAN_SECONDARY_SERVICE } from '../constants';
import { scanIpVirusTotal } from './virusTotalService';
import { scanIpAbuseIPDB } from './abuseIpdbService';
import { scanIpScamalytics } from './scamalyticsService';

let rateLimitTrackers: Partial<Record<ApiName, Record<string, ApiKeyUsage>>> = {};

const loadRateLimitTrackers = () => {
  Object.values(ApiName).forEach(serviceName => {
    rateLimitTrackers[serviceName] = {};
    try {
        const keys = Object.keys(localStorage);
        keys.forEach(key => {
            if (key.startsWith(`${LOCAL_STORAGE_RATE_LIMIT_STATE_PREFIX}${serviceName}_`)) {
                const apiKeyId = key.substring((`${LOCAL_STORAGE_RATE_LIMIT_STATE_PREFIX}${serviceName}_`).length);
                const storedState = localStorage.getItem(key);
                if (storedState) {
                    if(!rateLimitTrackers[serviceName]) rateLimitTrackers[serviceName] = {};
                    rateLimitTrackers[serviceName]![apiKeyId] = JSON.parse(storedState);
                }
            }
        });
    } catch (e) {
        console.error("Error loading rate limit trackers from localStorage:", e);
    }
  });
};

loadRateLimitTrackers();


const saveRateLimitTracker = (serviceName: ApiName, apiKeyId: string) => {
  if (rateLimitTrackers[serviceName] && rateLimitTrackers[serviceName]![apiKeyId]) {
    try {
      localStorage.setItem(`${LOCAL_STORAGE_RATE_LIMIT_STATE_PREFIX}${serviceName}_${apiKeyId}`, JSON.stringify(rateLimitTrackers[serviceName]![apiKeyId]));
    } catch (e) {
      console.error(`Error saving rate limit tracker for ${serviceName} key ${apiKeyId}:`, e);
    }
  }
};

function checkAndRecordRequest(serviceName: ApiName, apiKeyId: string): boolean {
  const serviceConfig = API_RATE_LIMITS[serviceName];
  const now = Date.now();
  const todayISO = new Date(now).toISOString().split('T')[0]; 

  if (!rateLimitTrackers[serviceName]) {
    rateLimitTrackers[serviceName] = {};
  }
  if (!rateLimitTrackers[serviceName]![apiKeyId]) {
    rateLimitTrackers[serviceName]![apiKeyId] = { minuteTimestamps: [], dailyCounts: {} };
  }

  const tracker = rateLimitTrackers[serviceName]![apiKeyId];

  tracker.minuteTimestamps = tracker.minuteTimestamps.filter(
    timestamp => now - timestamp < serviceConfig.periodMilliseconds
  );
  if (tracker.minuteTimestamps.length >= serviceConfig.requests) {
    return false; 
  }

  if (serviceConfig.dailyQuota) {
    if (!tracker.dailyCounts[todayISO]) {
      tracker.dailyCounts[todayISO] = 0;
    }
    Object.keys(tracker.dailyCounts).forEach(dateKey => {
        if (dateKey !== todayISO && (new Date(todayISO).getTime() - new Date(dateKey).getTime()) > 7 * 24 * 60 * 60 * 1000 ) {
            delete tracker.dailyCounts[dateKey];
        }
    });

    if (tracker.dailyCounts[todayISO] >= serviceConfig.dailyQuota) {
      return false; 
    }
  }

  tracker.minuteTimestamps.push(now);
  if (serviceConfig.dailyQuota) {
    tracker.dailyCounts[todayISO]++;
  }
  
  saveRateLimitTracker(serviceName, apiKeyId);
  return true; 
}

const getOverallSeverity = (results: ServiceScanResult[]): Severity => {
  if (!results || results.length === 0) {
    return Severity.UNKNOWN;
  }

  const contributingResults = results.filter(
    r => r.severity !== undefined &&
         r.status !== 'pending' &&
         r.status !== 'skipped' &&
         r.status !== 'not_found' && // Don't let 'not_found' (which has UNKNOWN severity) overly influence if other data exists
         r.status !== 'key_missing' &&
         r.status !== 'rate_limited'
  );
  
  // If all results are 'not_found' or 'skipped' or 'pending', overall is UNKNOWN
  if (contributingResults.length === 0) {
    if (results.every(r => r.status === 'not_found' || r.status === 'skipped' || r.status === 'pending' || r.status === 'key_missing' || r.status === 'rate_limited')) {
        return Severity.UNKNOWN;
    }
    // If there are errors but they don't have severity, also unknown
     if (results.some(r => r.status === 'error' && !r.severity)) {
        return Severity.UNKNOWN;
    }
  }


  const severities = contributingResults.map(r => r.severity as Severity);

  if (severities.includes(Severity.MALICIOUS)) return Severity.MALICIOUS;
  if (severities.includes(Severity.SUSPICIOUS)) return Severity.SUSPICIOUS;
  if (severities.includes(Severity.CLEAN)) return Severity.CLEAN;
  if (severities.includes(Severity.INFO)) return Severity.INFO;
  
  // If after all checks, only 'UNKNOWN' severities from successful/errored scans remain, then it's UNKNOWN
  // Or if contributingResults was empty and not all were non-contributing statuses (e.g. an error with UNKNOWN severity)
  return Severity.UNKNOWN;
};


const serviceScanFunctions: Record<ApiName, (ip: string, apiKey: string) => Promise<ServiceScanResult>> = {
  [ApiName.VIRUSTOTAL]: scanIpVirusTotal,
  [ApiName.ABUSEIPDB]: scanIpAbuseIPDB,
  [ApiName.SCAMALYTICS]: scanIpScamalytics,
};

export const scanIpConcurrently = async (
  ip: string,
  apiKeysFromContext: ApiKeyStore,
  id: string, 
  scanMode: ScanMode,
  onSingleServiceComplete: (result: ServiceScanResult) => void 
): Promise<AggregatedScanResult> => {
  
  const allServiceNames = Object.values(ApiName);
  let finalResultsForThisIp: ServiceScanResult[] = allServiceNames.map(name => ({
      serviceName: name, ip, status: 'pending', severity: Severity.UNKNOWN, idForService: `${id}-${name}` // Ensure unique key for react list
  }));

  const updateLocalFinalResults = (singleResult: ServiceScanResult) => {
      finalResultsForThisIp = finalResultsForThisIp.map(r => r.serviceName === singleResult.serviceName ? singleResult : r);
      onSingleServiceComplete({ ...singleResult, ip }); // Pass IP to ensure correct update in global history
  };

  const scanService = async (serviceName: ApiName): Promise<ServiceScanResult> => {
    const serviceScanFn = serviceScanFunctions[serviceName];
    const availableApiKeys: ApiKeyConfig[] = (apiKeysFromContext[serviceName] || [])
                                              .slice()
                                              .sort((a, b) => a.addedDate - b.addedDate); 

    if (availableApiKeys.length === 0) {
      return { serviceName, ip, status: 'key_missing', errorMessage: `No API Keys configured for ${serviceName}.`, severity: Severity.UNKNOWN };
    }

    for (const apiKeyConfig of availableApiKeys) {
      if (checkAndRecordRequest(serviceName, apiKeyConfig.id)) {
        try {
          const result = await serviceScanFn(ip, apiKeyConfig.key);
          return { ...result, usedApiKeyId: apiKeyConfig.id };
        } catch (error: any) {
          return { serviceName, ip, status: 'error', errorMessage: `Error scanning with ${serviceName}: ${error.message}`, severity: Severity.UNKNOWN, usedApiKeyId: apiKeyConfig.id };
        }
      }
    }
    return { serviceName, ip, status: 'rate_limited', errorMessage: `All API keys for ${serviceName} are rate limited.`, severity: Severity.UNKNOWN };
  };


  if (scanMode === ScanMode.SMART) {
    const primaryPromises = SMART_SCAN_PRIMARY_SERVICES.map(async (serviceName) => {
        const result = await scanService(serviceName);
        updateLocalFinalResults(result);
        return result;
    });
    const primaryResults = await Promise.all(primaryPromises);

    const suspiciousOrMaliciousCount = primaryResults.filter(r => r.severity === Severity.SUSPICIOUS || r.severity === Severity.MALICIOUS).length;
    
    if (suspiciousOrMaliciousCount >= 2) { 
      const skippedResult: ServiceScanResult = {
        serviceName: SMART_SCAN_SECONDARY_SERVICE, ip, status: 'skipped',
        skippedReason: `Skipped due to ${suspiciousOrMaliciousCount} prior suspicious/malicious results.`,
        severity: Severity.UNKNOWN 
      };
      updateLocalFinalResults(skippedResult);
    } else {
      const secondaryResult = await scanService(SMART_SCAN_SECONDARY_SERVICE);
      updateLocalFinalResults(secondaryResult);
    }
  } else { 
    const scanPromises = allServiceNames.map(async (serviceName) => {
        const result = await scanService(serviceName);
        updateLocalFinalResults(result);
        return result;
    });
    await Promise.all(scanPromises);
  }

  allServiceNames.forEach(serviceName => {
      if (!finalResultsForThisIp.find(fr => fr.serviceName === serviceName)) {
          console.warn(`Service ${serviceName} was missing from final results for IP ${ip}. Adding as error.`);
          updateLocalFinalResults({ serviceName, ip, status: 'error', errorMessage: 'Result processing error.', severity: Severity.UNKNOWN });
      }
  });

  return {
    id, ip, results: finalResultsForThisIp,
    overallSeverity: getOverallSeverity(finalResultsForThisIp),
    isScanning: false, 
  };
};