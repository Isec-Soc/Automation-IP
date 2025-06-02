
import { ServiceScanResult, Severity, ApiName, ScamalyticsSpecificData, ScamalyticsOperatorDetails, ScamalyticsLocationDetails, ScamalyticsDatacenterInfo, ScamalyticsExternalBlacklistInfo, ScamalyticsProxyDetails } from '../types';

const MOCK_DELAY = 900;

export const scanIpScamalytics = async (ip: string, apiKey: string): Promise<ServiceScanResult> => {
  // THIS IS A MOCK SERVICE. IT DOES NOT MAKE REAL API CALLS.
  await new Promise(resolve => setTimeout(resolve, MOCK_DELAY));

  if (!apiKey) {
    return {
      serviceName: ApiName.SCAMALYTICS, status: 'key_missing',
      errorMessage: 'API Key for Scamalytics not provided.', ip, severity: Severity.UNKNOWN,
    };
  }
  
  if (ip === "154.213.66.194") {
    const scamalyticsSpecific: ScamalyticsSpecificData = {
      fraudScore: 0,
      riskLevel: "low",
      riskDescription: `IP address ${ip} is operated by Octopus Web Solution Inc whose web traffic we consider to present a potentially low fraud risk. Non-web traffic may present a different risk or no risk at all. Scamalytics see low levels of traffic from Octopus Web Solution Inc across our global network, little of which we suspect to be potentially fraudulent. We have no visibility into the web traffic directly from ${ip}, and therefore apply a risk score of 0/100 based on the overall risk from Octopus Web Solution Inc’s IP addresses where we do have visibility. ${ip} is not a standard domestic connection, it is a commercial server which could be proxying traffic from another geographical location. The geographical location of ${ip} is in Hong Kong, however the geographical location of the user could be anywhere in the world.`,
      operatorDetails: { asn: "400619", ispName: "Arosscloud Inc", orgName: "Octopus Web Solution Inc", connectionType: "n/a" },
      locationDetails: { countryName: "Hong Kong", countryCode: "HK", state: "Sai Kung", city: "Tseung Kwan O", postalCode: "n/a", latitude: 22.3119, longitude: 114.257 },
      datacenterInfo: { isDatacenter: 'Unknown' },
      externalBlacklists: [
        { name: "Firehol", isListed: false }, { name: "IP2ProxyLite", isListed: false },
        { name: "IPsum", isListed: false }, { name: "Spamhaus", isListed: false },
        { name: "X4Bnet Spambot", isListed: false },
      ],
      proxyDetails: { isVpn: false, isTor: false, isPublicProxy: false, isWebProxy: false, isSearchEngineRobot: false, isServer: true },
      isBlacklistedExternal: false,
    };
    return {
      serviceName: ApiName.SCAMALYTICS, status: 'success', ip,
      severity: Severity.CLEAN, 
      score: 0,
      summary: `Fraud Score: 0. Potentially low fraud risk. Operated by Octopus Web Solution Inc. Located in Hong Kong.`,
      // Scamalytics doesn't have a public details URL pattern by IP
      scamalyticsSpecific,
      country: scamalyticsSpecific.locationDetails?.countryName,
      isp: scamalyticsSpecific.operatorDetails?.ispName,
      lastAnalysisDate: new Date().toLocaleDateString(),
    };
  }
   if (ip === "192.168.2.54") { // Example for a typically private IP
     return {
      serviceName: ApiName.SCAMALYTICS, status: 'success', ip, // Scamalytics might still give a score for private IPs based on its knowledge
      severity: Severity.CLEAN,
      score: 0,
      summary: 'Private IP address, generally considered safe by Scamalytics mock.',
      scamalyticsSpecific: {
        fraudScore: 0, riskLevel: "low",
        operatorDetails: { ispName: "Private Network"},
        locationDetails: { countryName: "N/A"},
        proxyDetails: { 
            isVpn: false, 
            isTor: false, 
            isPublicProxy: false, 
            isWebProxy: false, 
            isSearchEngineRobot: false, 
            isServer: false 
        }
      },
      country: "N/A", isp: "Private Network",
      lastAnalysisDate: new Date().toLocaleDateString(),
    };
  }

  try {
    const lastOctet = parseInt(ip.split('.').pop() || '0', 10);
    let severity = Severity.UNKNOWN;
    let summary = 'Scan results unavailable.';
    let scamScore = 0; 
    let riskLevel : ScamalyticsSpecificData['riskLevel'] = "unknown";

    const countries = [
        { name: 'United States', code: 'US' }, { name: 'Germany', code: 'DE' }, { name: 'United Kingdom', code: 'GB' }, 
        { name: 'Netherlands', code: 'NL' }, { name: 'France', code: 'FR' }
    ];
    const location: ScamalyticsLocationDetails = {
        countryName: countries[lastOctet % 5].name,
        countryCode: countries[lastOctet % 5].code,
        city: ['New York', 'Berlin', 'London', 'Amsterdam', 'Paris'][lastOctet % 5],
        state: ['NY', 'BE', 'ENG', 'NH', 'IDF'][lastOctet % 5],
        latitude: 20.0 + (lastOctet % 30),
        longitude: -20.0 + (lastOctet % 30),
    };
    const operator: ScamalyticsOperatorDetails = {
        asn: `AS${10000 + lastOctet}`,
        ispName: `Mock ISP Provider ${lastOctet % 10}`,
        orgName: `Mock Org Solutions ${lastOctet % 5}`,
        connectionType: ['Residential', 'Mobile', 'Corporate', 'Data Center'][lastOctet % 4],
    };


    if (lastOctet % 25 === 0 && ip !== "154.213.66.194") {
        summary = 'Scamalytics query limit reached or temporary error (mock).';
        riskLevel = "unknown";
        severity = Severity.UNKNOWN; // Or some other error status
        scamScore = -1; // Indicate error or unavailable
    } else if (lastOctet > 220) {
      severity = Severity.MALICIOUS; 
      scamScore = 90 + (lastOctet % 11);
      riskLevel = "very_high";
      summary = `Very high fraud risk score: ${scamScore}. Associated with significant fraudulent activity.`;
    } else if (lastOctet > 150) {
      severity = Severity.SUSPICIOUS; 
      scamScore = 70 + Math.floor((lastOctet % 71) / 3.5); 
      riskLevel = "high";
      summary = `High fraud risk score: ${scamScore}. Likely used for anonymity or has fraud indicators.`;
    } else if (lastOctet > 75) {
      severity = Severity.SUSPICIOUS; 
      scamScore = 30 + Math.floor((lastOctet % 76) / 2.5); 
      riskLevel = "medium";
      summary = `Medium fraud risk score: ${scamScore}. Some indicators of risky usage.`;
    } else {
      scamScore = lastOctet % 31; 
      riskLevel = scamScore > 10 ? "low" : "low"; 
      severity = scamScore > 10 ? Severity.INFO : Severity.CLEAN;
      summary = `Low fraud risk score: ${scamScore}. Generally considered safe.`;
      if (scamScore === 0) summary = 'No fraud risk detected.';
    }
    scamScore = Math.min(100, Math.max(0, scamScore));

    const scamalyticsSpecific: ScamalyticsSpecificData = {
        fraudScore: scamScore,
        riskLevel: riskLevel,
        riskDescription: summary, 
        operatorDetails: operator,
        locationDetails: location,
        datacenterInfo: { isDatacenter: operator.connectionType === 'Data Center' || lastOctet % 7 === 0 },
        externalBlacklists: [
            { name: "Firehol", isListed: scamScore > 80 && lastOctet % 2 === 0 },
            { name: "Spamhaus", isListed: scamScore > 85 },
        ],
        proxyDetails: {
            isVpn: scamScore > 60 && lastOctet % 3 === 0,
            isTor: scamScore > 90 && lastOctet % 4 === 0,
            isPublicProxy: scamScore > 70 && lastOctet % 2 !== 0,
            isWebProxy: scamScore > 65 && lastOctet % 5 === 0,
            isSearchEngineRobot: scamScore < 5 && lastOctet % 10 === 0,
            isServer: operator.connectionType === 'Data Center' || scamScore > 50,
        },
        isBlacklistedExternal: scamScore > 80,
    };


    return {
      serviceName: ApiName.SCAMALYTICS, status: 'success', ip,
      data: { score: scamScore, risk: riskLevel, ...scamalyticsSpecific }, 
      summary, severity, score: scamScore,
      scamalyticsSpecific,
      country: location.countryName,
      isp: operator.ispName,
      lastAnalysisDate: new Date().toLocaleDateString(),
    };
  } catch (e: any) {
    return {
      serviceName: ApiName.SCAMALYTICS, status: 'error', ip,
      errorMessage: `Mock data generation error: ${e.message}`,
      severity: Severity.UNKNOWN,
    };
  }
};
