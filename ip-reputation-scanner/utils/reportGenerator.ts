import { AggregatedScanResult, ServiceScanResult, Severity, VirusTotalVendorDetail, ApiName } from '../types';
import { SEVERITY_COLORS } from '../constants';

// Function to escape HTML special characters
const escapeHtml = (unsafe: string | undefined | null): string => {
  if (unsafe === undefined || unsafe === null) return 'N/A';
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

const getSeverityCssClasses = (severity: Severity | undefined, status?: ServiceScanResult['status']) => {
  if (status === 'skipped') return 'severity-SKIPPED';
  if (!severity) severity = Severity.UNKNOWN;
  if (status === 'not_found') return 'severity-INFO'; // Style 'not_found' like 'INFO' for less alarm
  
  const colorInfo = SEVERITY_COLORS[severity];
  return `severity-${severity}`;
};

const generateReportStyles = (): string => {
  let styles = `
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; background-color: #eef2f7; color: #1a202c; line-height: 1.6; }
    .container { max-width: 1100px; margin: auto; background-color: #ffffff; padding: 25px; border-radius: 10px; box-shadow: 0 6px 12px rgba(0,0,0,0.1); }
    h1 { color: #2c5282; text-align: center; border-bottom: 2px solid #4299e1; padding-bottom: 12px; margin-bottom: 25px; font-size: 2em; }
    .ip-card { background-color: #f7fafc; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 30px; padding: 20px; box-shadow: 0 3px 6px rgba(0,0,0,0.07); }
    .ip-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #cbd5e0; padding-bottom: 12px; margin-bottom: 18px; }
    .ip-address { font-size: 1.8em; font-weight: bold; color: #1a365d; word-break: break-all; }
    .overall-severity-badge { padding: 7px 14px; border-radius: 20px; font-weight: 600; font-size: 0.95em; text-transform: uppercase; }
    .service-results-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 18px; }
    .service-card { border: 1px solid #d1d5db; border-left-width: 6px; padding: 18px; border-radius: 6px; background-color: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    .service-name { font-size: 1.2em; font-weight: bold; margin-bottom: 10px; color: #2b6cb0; border-bottom: 1px dashed #e2e8f0; padding-bottom: 5px;}
    .detail-item { font-size: 0.88em; margin-bottom: 6px; color: #4a5568; }
    .detail-item strong { color: #2d3748; }
    .service-details-link { font-size: 0.85em; text-decoration: none; color: #3182ce; display: inline-block; margin-top: 10px; }
    .service-details-link:hover { text-decoration: underline; }
    .error-message, .status-message { color: #c53030; font-size: 0.9em; font-style: italic; margin-top:5px; }
    .skipped-message { color: #718096; font-size: 0.9em; font-style: italic; }
    .not-found-message { color: #0694a2; font-size: 0.9em; }
    .sub-heading { font-size: 0.9em; font-weight: bold; color: #374151; margin-top: 10px; margin-bottom: 5px; }
    ul.vendor-list, ul.blacklist { list-style: none; padding-left: 5px; font-size: 0.85em; max-height: 150px; overflow-y: auto; background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 8px; border-radius: 4px;}
    ul.vendor-list li, ul.blacklist li { padding: 2px 0; }
    .malicious { color: #c53030; font-weight: 500; }
    .suspicious { color: #d69e2e; font-weight: 500; }
    .clean { color: #38a169; font-weight: 500; }
    .unrated { color: #718096; }
  `;

  const colorMapping: Record<string, { bg: string; text: string; border: string }> = {
    'bg-green-100': { bg: '#f0fff4', text: '#2f855a', border: '#9ae6b4' },
    'bg-sky-100':   { bg: '#ebf8ff', text: '#2c5282', border: '#bee3f8' },
    'bg-yellow-100':{ bg: '#fffaf0', text: '#b7791f', border: '#f6e05e' },
    'bg-red-100':   { bg: '#fff5f5', text: '#c53030', border: '#feb2b2' },
    'bg-gray-100':  { bg: '#f7fafc', text: '#4a5568', border: '#e2e8f0' },
    'bg-slate-200': { bg: '#e2e8f0', text: '#4a5568', border: '#cbd5e0' }
  };

  Object.entries(SEVERITY_COLORS).forEach(([severityKey, tailwindColors]) => {
    const mapKey = tailwindColors.bg as keyof typeof colorMapping;
    const colors = colorMapping[mapKey] || colorMapping['bg-gray-100'];
    styles += `
      .severity-${severityKey} { /* For service-card border and overall-badge */
        border-left-color: ${colors.border} !important; 
      }
      .severity-${severityKey}-badge { /* For overall severity badge */
        background-color: ${colors.bg};
        color: ${colors.text};
        border: 1px solid ${colors.border};
      }
      .service-card.severity-${severityKey} { background-color: ${colors.bg}; }
    `;
  });
  return styles;
};

const renderDetailItem = (label: string, value: any): string => {
  if (value === undefined || value === null || value === '') return '';
  const displayValue = typeof value === 'boolean' ? (value ? 'Yes' : 'No') : escapeHtml(String(value));
  return `<div class="detail-item"><strong>${escapeHtml(label)}:</strong> ${displayValue}</div>`;
};

const renderVirusTotalDetails = (data: ServiceScanResult['virusTotalSpecific']): string => {
  if (!data) return '';
  let html = renderDetailItem('Detection Ratio', data.detectionRatio);
  html += renderDetailItem('Community Score', data.communityScore);
  html += renderDetailItem('AS Owner', data.asOwner);
  html += renderDetailItem('Country', data.country);
  if (data.lastAnalysisDate) html += renderDetailItem('Last Analysis', new Date(data.lastAnalysisDate).toLocaleString());

  if (data.vendorDetails && data.vendorDetails.length > 0) {
    html += '<div class="sub-heading">Vendor Analysis:</div><ul class="vendor-list">';
    data.vendorDetails.forEach(v => {
      let resultClass = '';
      if (v.result === 'Malicious') resultClass = 'malicious';
      else if (v.result === 'Suspicious') resultClass = 'suspicious';
      else if (v.result === 'Clean') resultClass = 'clean';
      else resultClass = 'unrated';
      html += `<li>${escapeHtml(v.vendorName)}: <span class="${resultClass}">${escapeHtml(v.result)}</span> ${v.category ? `(${escapeHtml(v.category)})` : ''}</li>`;
    });
    html += '</ul>';
  }
  return html;
};

const renderAbuseIPDBDetails = (data: ServiceScanResult['abuseIpdbSpecific'], country: string | undefined): string => {
  if (!data) return '';
  let html = renderDetailItem('ISP', data.isp);
  html += renderDetailItem('Usage Type', data.usageType);
  html += renderDetailItem('Domain', data.domainName);
  html += renderDetailItem('Country', country); // Use the common country field
  html += renderDetailItem('City', data.city);
  html += renderDetailItem('Total Reports', data.totalReports);
  html += renderDetailItem('Whitelisted', data.isWhitelisted);
  if (data.lastReportedAt) html += renderDetailItem('Last Reported', new Date(data.lastReportedAt).toLocaleString());
  return html;
};

const renderScamalyticsDetails = (data: ServiceScanResult['scamalyticsSpecific']): string => {
  if (!data) return '';
  let html = renderDetailItem('Risk Level', data.riskLevel?.toUpperCase());
  if(data.riskDescription) html += `<div class="detail-item"><strong>Description:</strong> <em>${escapeHtml(data.riskDescription)}</em></div>`;

  if (data.operatorDetails) {
    html += '<div class="sub-heading">Operator:</div>';
    html += renderDetailItem('ASN', data.operatorDetails.asn);
    html += renderDetailItem('ISP', data.operatorDetails.ispName);
    html += renderDetailItem('Organization', data.operatorDetails.orgName);
    html += renderDetailItem('Connection Type', data.operatorDetails.connectionType);
  }
  if (data.locationDetails) {
    html += '<div class="sub-heading">Location:</div>';
    html += renderDetailItem('Country', `${data.locationDetails.countryName} (${data.locationDetails.countryCode})`);
    html += renderDetailItem('City', data.locationDetails.city);
  }
  if (data.datacenterInfo) html += renderDetailItem('Datacenter', data.datacenterInfo.isDatacenter.toString());
  if (data.proxyDetails) {
    html += '<div class="sub-heading">Proxy/Anonymity:</div>';
    html += renderDetailItem('VPN', data.proxyDetails.isVpn);
    html += renderDetailItem('Tor Exit Node', data.proxyDetails.isTor);
    // ... add other proxy details
     html += renderDetailItem('Server Connection', data.proxyDetails.isServer);
  }
  if (data.externalBlacklists && data.externalBlacklists.length > 0) {
    html += '<div class="sub-heading">External Blacklists:</div><ul class="blacklist">';
    data.externalBlacklists.forEach(bl => {
      html += `<li>${escapeHtml(bl.name)}: <span class="${bl.isListed ? 'malicious' : 'clean'}">${bl.isListed ? 'Listed' : 'Not Listed'}</span></li>`;
    });
    html += '</ul>';
  }
  return html;
};


const renderServiceResult = (result: ServiceScanResult): string => {
  const severity = result.severity || Severity.UNKNOWN;
  const cardClasses = getSeverityCssClasses(severity, result.status);

  let content = '';
  switch (result.status) {
    case 'success':
      content = `<div class="detail-item"><strong>Status:</strong> <span class="${getSeverityCssClasses(severity)}">${escapeHtml(severity)}</span></div>`;
      if (result.score !== undefined) content += renderDetailItem('Score', result.score);
      if (result.summary && !result.scamalyticsSpecific?.riskDescription) content += `<div class="detail-item"><strong>Summary:</strong> <em>${escapeHtml(result.summary)}</em></div>`;
      
      if (result.serviceName === ApiName.VIRUSTOTAL) content += renderVirusTotalDetails(result.virusTotalSpecific);
      else if (result.serviceName === ApiName.ABUSEIPDB) content += renderAbuseIPDBDetails(result.abuseIpdbSpecific, result.country);
      else if (result.serviceName === ApiName.SCAMALYTICS) content += renderScamalyticsDetails(result.scamalyticsSpecific);
      
      if (result.detailsUrl) content += `<a href="${escapeHtml(result.detailsUrl)}" target="_blank" rel="noopener noreferrer" class="service-details-link">View Full Report on ${escapeHtml(result.serviceName)} &rarr;</a>`;
      break;
    case 'pending':
      content = `<div class="status-message">Scanning...</div>`;
      break;
    case 'key_missing': content = `<div class="error-message"><strong>Key Missing:</strong> ${escapeHtml(result.errorMessage)}</div>`; break;
    case 'rate_limited': content = `<div class="error-message"><strong>Rate Limited:</strong> ${escapeHtml(result.errorMessage)}</div>`; break;
    case 'error': content = `<div class="error-message"><strong>Error:</strong> ${escapeHtml(result.errorMessage)}</div>`; break;
    case 'skipped': content = `<div class="skipped-message"><strong>Skipped:</strong> ${escapeHtml(result.skippedReason)}</div>`; break;
    case 'not_found':
      content = `<div class="not-found-message"><strong>Not Found:</strong> ${escapeHtml(result.summary || "IP not found in dataset.")}</div>`;
      if (result.serviceName === ApiName.ABUSEIPDB) content += renderAbuseIPDBDetails(result.abuseIpdbSpecific, result.country); // Show context for AbuseIPDB not found
      if (result.detailsUrl) content += `<a href="${escapeHtml(result.detailsUrl)}" target="_blank" rel="noopener noreferrer" class="service-details-link">Check on ${escapeHtml(result.serviceName)} &rarr;</a>`;
      break;
    default:
      content = `<div class="status-message">Status: ${escapeHtml(result.status)}.</div>`;
  }

  return `
    <div class="service-card ${cardClasses}">
      <h4 class="service-name">${escapeHtml(result.serviceName)}</h4>
      ${content}
    </div>
  `;
};

export const generateHtmlReport = (scanHistory: AggregatedScanResult[]): string => {
  const reportDate = new Date().toLocaleString();
  const styles = generateReportStyles();

  const ipCardsHtml = scanHistory
    .filter(scanData => !scanData.isScanning && !scanData.error) // Only include completed and non-errored top-level scans
    .sort((a,b) => parseInt(a.id.split('-')[0]) - parseInt(b.id.split('-')[0])) 
    .map(scanData => {
    const overallSeverity = scanData.overallSeverity || Severity.UNKNOWN;
    const overallSeverityBadgeClasses = `overall-severity-badge severity-${overallSeverity}-badge`;
    
    const serviceResultsHtml = scanData.results.length > 0
      ? scanData.results.map(renderServiceResult).join('')
      : '<p class="status-message">No scan results available for this IP.</p>';

    return `
      <div class="ip-card">
        <div class="ip-header">
          <h3 class="ip-address">${escapeHtml(scanData.ip)}</h3>
          <span class="${overallSeverityBadgeClasses}">${escapeHtml(overallSeverity)}</span>
        </div>
        <div class="service-results-grid">${serviceResultsHtml}</div>
      </div>
    `;
  }).join('');
  
  const errorScansHtml = scanHistory
    .filter(scanData => scanData.error)
    .map(scanData => `
        <div class="ip-card severity-Malicious"> <!-- Generic error styling -->
            <div class="ip-header">
              <h3 class="ip-address">${escapeHtml(scanData.ip)}</h3>
              <span class="overall-severity-badge severity-Malicious-badge">ERROR</span>
            </div>
            <p class="error-message">${escapeHtml(scanData.error)}</p>
        </div>
    `).join('');


  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>IP Reputation Scan Report - ${reportDate}</title>
      <style>
        ${styles}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>IP Reputation Scan Report</h1>
        <p style="text-align:center; margin-bottom:20px; font-size:0.9em; color:#555;">Generated on: ${reportDate}</p>
        ${ipCardsHtml}
        ${errorScansHtml.length > 0 ? `<h2>Scan Errors</h2>${errorScansHtml}` : ''}
        <footer style="text-align:center; margin-top:30px; padding-top:15px; border-top:1px solid #eee; font-size:0.8em; color:#777;">
          IP Reputation Scanner (Mock Data Simulation)
        </footer>
      </div>
    </body>
    </html>
  `;
};