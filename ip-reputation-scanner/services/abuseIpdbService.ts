
import { ServiceScanResult, Severity, ApiName, AbuseIPDBSpecificData } from '../types';

const MOCK_DELAY = 700;

export const scanIpAbuseIPDB = async (ip: string, apiKey: string): Promise<ServiceScanResult> => {
  // THIS IS A MOCK SERVICE. IT DOES NOT MAKE REAL API CALLS.
  await new Promise(resolve => setTimeout(resolve, MOCK_DELAY));

  if (!apiKey) {
    return {
      serviceName: ApiName.ABUSEIPDB, status: 'key_missing',
      errorMessage: 'API Key for AbuseIPDB not provided.', ip, severity: Severity.UNKNOWN,
    };
  }
  
  if (ip === "185.107.56.167") {
    const abuseIpdbSpecific: AbuseIPDBSpecificData = {
        isp: "Serverhosting", 
        usageType: "Data Center/Web Hosting/Transit",
        domainName: "nforce.com",
        countryCode: "NL",
        city: "Roosendaal, North Brabant",
        totalReports: 0,
        isWhitelisted: false,
        lastReportedAt: undefined,
    };
    return {
      serviceName: ApiName.ABUSEIPDB, status: 'not_found', ip,
      summary: `${ip} was not found in our database.`,
      severity: Severity.UNKNOWN,
      score: 0, 
      detailsUrl: `https://www.abuseipdb.com/check/${ip}`, // Link for user, not for fetch
      abuseIpdbSpecific,
      country: "Netherlands", 
      isp: abuseIpdbSpecific.isp,
    };
  }
   if (ip === "192.168.2.54") { // Example for a typically private IP
     return {
      serviceName: ApiName.ABUSEIPDB, status: 'not_found', ip,
      summary: 'IP address is private or not found in AbuseIPDB dataset.', severity: Severity.UNKNOWN,
      score: 0,
      detailsUrl: `https://www.abuseipdb.com/check/${ip}`,
      abuseIpdbSpecific: { isp: "Private Network", usageType: "Private", countryCode: "N/A", totalReports: 0 },
      country: "N/A", isp: "Private Network",
    };
  }

  try {
    const lastOctet = parseInt(ip.split('.').pop() || '0', 10);
    let severity = Severity.UNKNOWN;
    let summary = 'No abuse reports found.';
    let abuseConfidenceScore = 0;
    
    const countries = [
        { code: 'US', name: 'United States' }, 
        { code: 'CN', name: 'China' }, 
        { code: 'RU', name: 'Russia' }, 
        { code: 'BR', name: 'Brazil' }, 
        { code: 'IN', name: 'India' }
    ];
    const countryInfo = countries[lastOctet % 5];
    
    const usageTypes = ["Data Center/Web Hosting/Transit", "Fixed Line ISP", "Mobile ISP", "Commercial"];
    const currentUsageType = usageTypes[lastOctet % 4];
    const currentISP = `Mock ISP for ${countryInfo.code} (${currentUsageType})`;
    const currentDomain = `domain-${lastOctet}.example.com`;
    const currentCity = ["New York", "Beijing", "Moscow", "Sao Paulo", "Mumbai"][lastOctet % 5];


    if (lastOctet % 20 === 0 && ip !== "185.107.56.167") { 
      return {
        serviceName: ApiName.ABUSEIPDB, status: 'not_found', ip,
        summary: 'IP address not found or private.', severity: Severity.UNKNOWN,
        score: 0,
        detailsUrl: `https://www.abuseipdb.com/check/${ip}`,
        abuseIpdbSpecific: { 
            isp: currentISP, usageType: currentUsageType, domainName: currentDomain, 
            countryCode: countryInfo.code, city: currentCity, totalReports: 0, isWhitelisted: false 
        },
        country: countryInfo.name, isp: currentISP,
      };
    } else if (lastOctet > 180) {
      severity = Severity.MALICIOUS;
      abuseConfidenceScore = 90 + (lastOctet % 11); 
      summary = `High abuse confidence score: ${abuseConfidenceScore}%. Numerous reports of malicious activity.`;
    } else if (lastOctet > 90) {
      severity = Severity.SUSPICIOUS;
      abuseConfidenceScore = 50 + (lastOctet % 41); 
      summary = `Moderate abuse confidence score: ${abuseConfidenceScore}%. Some reports of suspicious activity.`;
    } else {
      severity = Severity.CLEAN;
      abuseConfidenceScore = lastOctet % 51; 
      summary = `Low abuse confidence score: ${abuseConfidenceScore}%. Likely clean.`;
    }
    abuseConfidenceScore = Math.min(100, Math.max(0, abuseConfidenceScore));

    const abuseIpdbSpecific: AbuseIPDBSpecificData = {
        isp: currentISP,
        usageType: currentUsageType,
        domainName: abuseConfidenceScore > 10 ? currentDomain : undefined, 
        countryCode: countryInfo.code,
        city: currentCity,
        totalReports: Math.floor(abuseConfidenceScore / 10) * (5 + (lastOctet % 10)),
        isWhitelisted: abuseConfidenceScore < 10 && lastOctet % 10 === 0, 
        lastReportedAt: abuseConfidenceScore > 0 ? new Date(Date.now() - (lastOctet * 1000 * 3600 * 12)).toISOString() : undefined,
    };

    return {
      serviceName: ApiName.ABUSEIPDB, status: 'success', ip,
      data: { data: { ipAddress: ip, abuseConfidenceScore, ...abuseIpdbSpecific } }, 
      summary, severity, score: abuseConfidenceScore,
      detailsUrl: `https://www.abuseipdb.com/check/${ip}`,
      abuseIpdbSpecific,
      country: countryInfo.name,
      isp: abuseIpdbSpecific.isp,
      lastAnalysisDate: abuseIpdbSpecific.lastReportedAt ? new Date(abuseIpdbSpecific.lastReportedAt).toLocaleString() : 'N/A',
    };
  } catch (e: any) {
     return {
      serviceName: ApiName.ABUSEIPDB, status: 'error', ip,
      errorMessage: `Mock data generation error: ${e.message}`,
      severity: Severity.UNKNOWN,
    };
  }
};
