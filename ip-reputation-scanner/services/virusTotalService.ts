
import { ServiceScanResult, Severity, ApiName, VirusTotalSpecificData, VirusTotalVendorDetail } from '../types';

const MOCK_DELAY = 800; // milliseconds

const generateVendorDetails = (ip: string, maliciousCount: number, suspiciousCount: number, cleanCount: number): VirusTotalVendorDetail[] => {
  const vendors = [
    "alphaMountain.ai", "BitDefender", "CRDF", "CyRadar", "Forcepoint ThreatSeeker", "G-Data", "Gridinsoft", "Lionic", "VIPRE", "Webroot", // Malicious prone
    "ArcSight Threat Intelligence", "GCP Abuse Intelligence", // Suspicious prone
    "Abusix", "Acronis", "ADMINUSLabs", "AILabs (MONITORAPP)", "AlienVault", "Antiy-AVL", "benkow.cc", "Blueliv", "Certego", "Chong Lua Dao", "CINS Army", "CMC Threat Intelligence", "Criminal IP", "Cyble", "desenmascara.me", "DNS8", "Dr.Web", "EmergingThreats", "Emsisoft", "ESET", "ESTsecurity", "Fortinet", "Google Safebrowsing", "GreenSnow", "Heimdal Security", "IPsum", "Juniper Networks", "Malwared", "MalwarePatrol", "malwares.com URL checker", "OpenPhish", "Phishing Database", "Phishtank", "PREBYTES", "Quick Heal", "Quttera", "Scantitan", "SCUMWARE.org", "Seclookup", "securolytics", "Snort IP sample list", "SOCRadar", "Sophos", "Spam404", "StopForumSpam", "Sucuri SiteCheck", "ThreatHive", "Threatsourcing", "Trustwave", "URLhaus", "Viettel Threat Intelligence", "ViriBack", "VX Vault", "Yandex Safebrowsing", "ZeroCERT", // Clean prone
    "0xSI_f33d", "AlphaSOC", "AutoShun", "Axur", "Bfore.Ai PreCrime", "Bkav", "Cluster25", "CSIS Security Group", "Cyan", "Ermes", "Hunt.io Intelligence", "Kaspersky", "Lumu", "MalwareURL", "Mimecast", "Netcraft", "PhishFort", "PhishLabs", "PrecisionSec", "SafeToOpen", "Sansec eComscan", "SecureBrain", "Underworld", "URLQuery", "Xcitium Verdict Cloud", "ZeroFox", "zvelo" // Unrated prone
  ];
  
  const details: VirusTotalVendorDetail[] = [];
  let mAssigned = 0, sAssigned = 0, cAssigned = 0;

  // Shuffle vendors to make assignments more random for mock display
  const shuffledVendors = [...vendors].sort(() => 0.5 - Math.random());

  for (const vendor of shuffledVendors) {
    if (mAssigned < maliciousCount) {
      details.push({ vendorName: vendor, result: 'Malicious', category: (Math.random() > 0.5 ? 'Malware' : 'Phishing') });
      mAssigned++;
    } else if (sAssigned < suspiciousCount) {
      details.push({ vendorName: vendor, result: 'Suspicious', category: (Math.random() > 0.5 ? 'Miner' : 'Riskware')});
      sAssigned++;
    } else if (cAssigned < cleanCount) {
      details.push({ vendorName: vendor, result: 'Clean' });
      cAssigned++;
    } else {
      details.push({ vendorName: vendor, result: 'Unrated' });
    }
  }
  return details.sort((a,b) => a.vendorName.localeCompare(b.vendorName)); // Sort for consistency
};


export const scanIpVirusTotal = async (ip: string, apiKey: string): Promise<ServiceScanResult> => {
  // THIS IS A MOCK SERVICE. IT DOES NOT MAKE REAL API CALLS.
  await new Promise(resolve => setTimeout(resolve, MOCK_DELAY));

  if (!apiKey) {
    return {
      serviceName: ApiName.VIRUSTOTAL, status: 'key_missing',
      errorMessage: 'API Key for VirusTotal not provided.', ip, severity: Severity.UNKNOWN,
    };
  }

  // Specific mock for 188.114.96.0 to match user example
  if (ip === "188.114.96.0") {
    const maliciousCount = 10;
    const totalEngines = 94;
    const suspiciousCount = 2; // Example
    const cleanCount = totalEngines - maliciousCount - suspiciousCount - 5; // some unrated

    const specificData: VirusTotalSpecificData = {
      detectionRatio: `${maliciousCount}/${totalEngines}`,
      communityScore: -193, // Example
      asOwner: "AS13335 (CLOUDFLARENET)",
      country: "US", // Example
      lastAnalysisDate: new Date(Date.now() - 3600 * 1000).toISOString(), // 1 hour ago
      vendorDetails: generateVendorDetails(ip, maliciousCount, suspiciousCount, cleanCount)
    };
    return {
      serviceName: ApiName.VIRUSTOTAL, status: 'success', ip,
      severity: Severity.MALICIOUS, score: maliciousCount,
      summary: `${maliciousCount}/${totalEngines} security vendors flagged this IP address as malicious.`,
      detailsUrl: `https://www.virustotal.com/gui/ip-address/${ip}`, // Link for user, not for fetch
      virusTotalSpecific: specificData,
      country: specificData.country,
      lastAnalysisDate: new Date(specificData.lastAnalysisDate!).toLocaleString(),
      isp: specificData.asOwner,
    };
  }
  
  const lastOctet = parseInt(ip.split('.').pop() || '0', 10);

  // Simulate "not found" for specific patterns or user example request
   if (ip === "192.168.2.54") { // Example for a typically private IP
     return {
      serviceName: ApiName.VIRUSTOTAL, status: 'not_found', ip,
      summary: 'IP address is private or not found in VirusTotal dataset.', severity: Severity.UNKNOWN,
      detailsUrl: `https://www.virustotal.com/gui/ip-address/${ip}`,
      virusTotalSpecific: { lastAnalysisDate: new Date().toISOString(), country: "N/A" }
    };
  }
  if (lastOctet === 100 || ip.endsWith(".100")) { // Example of "not found"
    return {
      serviceName: ApiName.VIRUSTOTAL, status: 'not_found', ip,
      summary: 'IP address not found in VirusTotal dataset.', severity: Severity.UNKNOWN,
      detailsUrl: `https://www.virustotal.com/gui/ip-address/${ip}`,
      virusTotalSpecific: { lastAnalysisDate: new Date().toISOString(), country: "N/A" }
    };
  }
  if (lastOctet % 15 === 0 && ip !== "188.114.96.0") { 
     return {
      serviceName: ApiName.VIRUSTOTAL, status: 'not_found', ip,
      summary: 'IP address not found in VirusTotal dataset.', severity: Severity.UNKNOWN,
      detailsUrl: `https://www.virustotal.com/gui/ip-address/${ip}`,
      virusTotalSpecific: { lastAnalysisDate: new Date().toISOString(), country: "N/A" }
    };
  }

  try {
    let severity = Severity.UNKNOWN;
    let summary = 'No analysis data found.';
    let maliciousCount = 0;
    let suspiciousCount = 0;
    const totalEngines = 70 + (lastOctet % 25); // Vary total engines
    let cleanCount = 0;

    if (lastOctet > 200) {
      severity = Severity.MALICIOUS;
      maliciousCount = 10 + (lastOctet % 15);
      suspiciousCount = 2 + (lastOctet % 5);
      summary = `High risk: ${maliciousCount} engines detected threats.`;
    } else if (lastOctet > 100) {
      severity = Severity.SUSPICIOUS;
      maliciousCount = 1 + (lastOctet % 3);
      suspiciousCount = 5 + (lastOctet % 10);
      summary = `Moderate risk: ${suspiciousCount} engines detected potential threats.`;
    } else {
      severity = Severity.CLEAN;
      maliciousCount = 0;
      suspiciousCount = lastOctet % 2;
      summary = 'Low risk: No significant threats detected by most engines.';
    }
    
    cleanCount = Math.max(0, totalEngines - maliciousCount - suspiciousCount - (lastOctet % 5)); // some unrated

    const virusTotalSpecific: VirusTotalSpecificData = {
      detectionRatio: `${maliciousCount}/${totalEngines}`,
      communityScore: (maliciousCount * -10) + (suspiciousCount * -5) + (cleanCount * 1) + (lastOctet % 50 - 25),
      asOwner: `AS${1000 + (lastOctet % 500)} Mock ISP Inc.`,
      country: ['US', 'CA', 'GB', 'DE', 'JP'][lastOctet % 5],
      lastAnalysisDate: new Date(Date.now() - (lastOctet * 1000 * 3600 * 24)).toISOString(),
      vendorDetails: generateVendorDetails(ip, maliciousCount, suspiciousCount, cleanCount)
    };

    return {
      serviceName: ApiName.VIRUSTOTAL, status: 'success', ip,
      data: { attributes: { ...virusTotalSpecific } }, 
      summary, severity, score: maliciousCount,
      detailsUrl: `https://www.virustotal.com/gui/ip-address/${ip}`,
      virusTotalSpecific,
      country: virusTotalSpecific.country,
      lastAnalysisDate: new Date(virusTotalSpecific.lastAnalysisDate!).toLocaleString(),
      isp: virusTotalSpecific.asOwner,
    };
  } catch (e: any) {
    return {
      serviceName: ApiName.VIRUSTOTAL, status: 'error', ip,
      errorMessage: `Mock data generation error: ${e.message}`,
      severity: Severity.UNKNOWN,
    };
  }
};
