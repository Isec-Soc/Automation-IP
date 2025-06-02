import React from 'react';
import { AggregatedScanResult, ServiceScanResult, Severity, ApiName, VirusTotalVendorDetail } from '../types';
import { SEVERITY_COLORS } from '../constants';
import {
  CheckCircleIcon, ExclamationTriangleIcon, NoSymbolIcon, QuestionMarkCircleIcon, ExternalLinkIcon,
  ClockIcon, InformationCircleIcon, ShieldExclamationIcon, ServerIcon, WifiIcon, UserGroupIcon, GlobeAltIcon, MapPinIcon, BuildingLibraryIcon, EyeIcon as LinkIcon, ListBulletIcon as VendorListIcon, MinusCircleIcon, QuestionMarkCircleIcon as HelpIcon, CircleStackIcon
} from './Icons';
import LoadingSpinner from './LoadingSpinner';

interface IpResultCardProps {
  scanData: AggregatedScanResult;
}

const SeverityIcon: React.FC<{ severity: Severity; className?: string }> = ({ severity, className = "w-6 h-6" }) => {
  const baseClasses = `${className} inline-block mr-2`;
  switch (severity) {
    case Severity.CLEAN:
      return <CheckCircleIcon className={`${baseClasses} text-green-500`} />;
    case Severity.INFO:
      return <InformationCircleIcon className={`${baseClasses} text-sky-500`} />;
    case Severity.SUSPICIOUS:
      return <ExclamationTriangleIcon className={`${baseClasses} text-yellow-500`} />;
    case Severity.MALICIOUS:
      return <NoSymbolIcon className={`${baseClasses} text-red-500`} />;
    default:
      return <QuestionMarkCircleIcon className={`${baseClasses} text-gray-500`} />;
  }
};

const DetailItem: React.FC<{label: string; value?: string | number | boolean | null; children?: React.ReactNode; className?: string}> = ({ label, value, children, className }) => {
    if (value === undefined && !children) return null;
    return (
        <p className={`text-xs text-slate-300 mb-1 ${className}`}>
            <strong className="text-slate-200">{label}:</strong>{' '}
            {children || (typeof value === 'boolean' ? (value ? 'Yes' : 'No') : escapeHtml(value?.toString()))}
        </p>
    );
};
const escapeHtml = (unsafe: string | undefined | null): string => {
  if (unsafe === undefined || unsafe === null) return 'N/A';
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};


const VirusTotalResultDisplay: React.FC<{ result: ServiceScanResult }> = ({ result }) => {
  const vtData = result.virusTotalSpecific;
  if (!vtData) return <DetailItem label="Details" value="Not available" />;

  const renderVendor = (vendor: VirusTotalVendorDetail, index: number) => {
    let colorClass = "text-slate-400";
    if (vendor.result === "Malicious") colorClass = "text-red-400";
    else if (vendor.result === "Suspicious") colorClass = "text-yellow-400";
    else if (vendor.result === "Clean") colorClass = "text-green-400";

    return (
        <li key={index} className={`text-xs py-0.5 ${colorClass}`}>
            {vendor.vendorName}: <span className="font-semibold">{vendor.result}</span> {vendor.category && `(${vendor.category})`}
        </li>
    );
  };

  return (
    <>
      <DetailItem label="Detection Ratio" value={vtData.detectionRatio} className="font-semibold text-base" />
      {vtData.communityScore !== undefined && <DetailItem label="Community Score" value={vtData.communityScore} />}
      <DetailItem label="AS Owner" value={vtData.asOwner} />
      <DetailItem label="Country" value={vtData.country} />
      {vtData.lastAnalysisDate && <DetailItem label="Last Analysis" value={new Date(vtData.lastAnalysisDate).toLocaleString()} />}
      
      {vtData.vendorDetails && vtData.vendorDetails.length > 0 && (
        <div className="mt-2">
          <h5 className="text-xs font-semibold text-slate-200 mb-1 flex items-center"><VendorListIcon className="w-3 h-3 mr-1"/>Vendor Analysis:</h5>
          <ul className="list-disc list-inside max-h-32 overflow-y-auto bg-slate-800 p-1 rounded text-slate-400">
            {vtData.vendorDetails.map(renderVendor)}
          </ul>
        </div>
      )}
    </>
  );
};

const AbuseIPDBResultDisplay: React.FC<{ result: ServiceScanResult }> = ({ result }) => {
  const adbData = result.abuseIpdbSpecific;
  if (!adbData) return <DetailItem label="Details" value="Not available" />;
  
  if (result.status === 'not_found') {
     return (
        <>
          <p className="text-sm text-slate-300 mb-1">{result.summary || "IP address not found."}</p>
          <DetailItem label="ISP" value={adbData.isp} />
          <DetailItem label="Usage Type" value={adbData.usageType} />
          <DetailItem label="Domain" value={adbData.domainName} />
          <DetailItem label="Country" value={result.country} />
          <DetailItem label="City" value={adbData.city} />
        </>
     );
  }

  return (
    <>
      <DetailItem label="ISP" value={adbData.isp} />
      <DetailItem label="Usage Type" value={adbData.usageType} />
      <DetailItem label="Domain" value={adbData.domainName} />
      <DetailItem label="Country" value={result.country} />
      <DetailItem label="City" value={adbData.city} />
      {adbData.totalReports !== undefined && <DetailItem label="Total Reports" value={adbData.totalReports} />}
      {adbData.isWhitelisted !== undefined && <DetailItem label="Whitelisted" value={adbData.isWhitelisted ? "Yes" : "No"} />}
      {adbData.lastReportedAt && <DetailItem label="Last Reported" value={new Date(adbData.lastReportedAt).toLocaleString()} />}
    </>
  );
};

const ScamalyticsResultDisplay: React.FC<{ result: ServiceScanResult }> = ({ result }) => {
  const scData = result.scamalyticsSpecific;
  if (!scData) return <DetailItem label="Details" value="Not available" />;

  return (
    <div className="space-y-1">
      {scData.riskLevel && <DetailItem label="Risk Level" value={scData.riskLevel.toUpperCase()} className={`font-semibold ${scData.riskLevel === 'low' ? 'text-green-400' : scData.riskLevel === 'medium' ? 'text-yellow-400' : (scData.riskLevel === 'high' || scData.riskLevel === 'very_high') ? 'text-red-400' : 'text-slate-300'}`} />}
      {scData.riskDescription && <p className="text-xs text-slate-400 italic mt-1 mb-2">{scData.riskDescription}</p>}

      {scData.operatorDetails && (
        <>
          <h5 className="text-xs font-semibold text-slate-200 mt-2 flex items-center"><ServerIcon className="w-3 h-3 mr-1"/>Operator:</h5>
          <DetailItem label="ASN" value={scData.operatorDetails.asn} />
          <DetailItem label="ISP" value={scData.operatorDetails.ispName} />
          <DetailItem label="Organization" value={scData.operatorDetails.orgName} />
          <DetailItem label="Connection Type" value={scData.operatorDetails.connectionType} />
        </>
      )}
      {scData.locationDetails && (
        <>
          <h5 className="text-xs font-semibold text-slate-200 mt-2 flex items-center"><MapPinIcon className="w-3 h-3 mr-1"/>Location:</h5>
          <DetailItem label="Country" value={`${scData.locationDetails.countryName} (${scData.locationDetails.countryCode})`} />
          <DetailItem label="City" value={scData.locationDetails.city} />
           {scData.locationDetails.latitude !== undefined && scData.locationDetails.longitude !== undefined && 
            <DetailItem label="Coords" value={`${scData.locationDetails.latitude?.toFixed(4)}, ${scData.locationDetails.longitude?.toFixed(4)}`} />
          }
        </>
      )}
       {scData.datacenterInfo && <DetailItem label="Datacenter" value={scData.datacenterInfo.isDatacenter.toString()} />}
       {scData.proxyDetails && (
        <>
          <h5 className="text-xs font-semibold text-slate-200 mt-2 flex items-center"><ShieldExclamationIcon className="w-3 h-3 mr-1"/>Proxy/Anonymity:</h5>
          <DetailItem label="VPN" value={scData.proxyDetails.isVpn} />
          <DetailItem label="Tor Exit Node" value={scData.proxyDetails.isTor} />
          <DetailItem label="Public Proxy" value={scData.proxyDetails.isPublicProxy} />
          <DetailItem label="Web Proxy" value={scData.proxyDetails.isWebProxy} />
          <DetailItem label="Server Connection" value={scData.proxyDetails.isServer} />
        </>
      )}
      {scData.externalBlacklists && scData.externalBlacklists.length > 0 && (
        <>
          <h5 className="text-xs font-semibold text-slate-200 mt-2 flex items-center"><CircleStackIcon className="w-3 h-3 mr-1"/>External Blacklists:</h5>
          <ul className="list-none pl-0 text-xs">
            {scData.externalBlacklists.map((bl, i) => (
              <li key={i}>{bl.name}: <span className={bl.isListed ? "text-red-400 font-semibold" : "text-green-400"}>{bl.isListed ? "Listed" : "Not Listed"}</span></li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
};


const ServiceResultDisplay: React.FC<{ result: ServiceScanResult }> = ({ result }) => {
  const severity = result.severity || Severity.UNKNOWN;
  const severityStyles = SEVERITY_COLORS[severity === Severity.UNKNOWN && result.status === 'skipped' ? 'SKIPPED' : severity];
  
  const renderContent = () => {
    switch (result.serviceName) {
      case ApiName.VIRUSTOTAL: return <VirusTotalResultDisplay result={result} />;
      case ApiName.ABUSEIPDB: return <AbuseIPDBResultDisplay result={result} />;
      case ApiName.SCAMALYTICS: return <ScamalyticsResultDisplay result={result} />;
      default: return <p className="text-xs text-slate-400">Detailed data not available.</p>;
    }
  };

  const renderStatusSpecificContent = () => {
    switch (result.status) {
      case 'pending':
        return <LoadingSpinner size="sm" text={`Scanning...`} />;
      case 'key_missing':
        return <p className="text-xs text-yellow-400">{result.errorMessage}</p>;
      case 'rate_limited':
        return (
            <div className="flex items-center text-xs text-orange-400">
                <ClockIcon className="w-4 h-4 mr-1"/> {result.errorMessage}
            </div>
        );
      case 'error':
        return <p className="text-xs text-red-400">{result.errorMessage || 'An unknown error occurred.'}</p>;
      case 'not_found':
         return (
            <>
              <div className="flex items-center mb-1">
                <HelpIcon className="w-5 h-5 mr-2 text-sky-400" />
                <span className={`text-sm font-semibold text-sky-300`}>
                  Not Found
                </span>
              </div>
              <p className="text-xs text-slate-300 mb-1 leading-relaxed">{result.summary || 'IP not found in dataset.'}</p>
              {result.serviceName === ApiName.ABUSEIPDB && <AbuseIPDBResultDisplay result={result} /> /* Show context info for AbuseIPDB not found */}
              {result.detailsUrl && (
                <a href={result.detailsUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center mt-2 text-xs text-primary-light hover:text-primary">
                  Check on {result.serviceName} <LinkIcon className="w-3 h-3 ml-1" />
                </a>
              )}
            </>
          );
      case 'skipped':
        return (
            <div className="flex items-center text-xs text-slate-400">
                <MinusCircleIcon className="w-4 h-4 mr-1"/> Skipped: {result.skippedReason || "Scan skipped."}
            </div>
        );
      case 'success':
        return (
          <>
            <div className="flex items-center mb-1">
              <SeverityIcon severity={severity} className="w-5 h-5 mr-0" />
              <span className={`text-sm font-semibold ${severityStyles.text}`}>
                {severity}
                {result.score !== undefined && ` (Score: ${result.score})`}
              </span>
            </div>
            {result.summary && !result.scamalyticsSpecific?.riskDescription && /* Don't show generic summary if detailed Scamalytics desc exists */
                <p className="text-xs text-slate-400 mb-1 leading-relaxed italic">{result.summary}</p>
            }
            {renderContent()}
            {result.detailsUrl && (
              <a
                href={result.detailsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center mt-3 text-xs text-primary-light hover:text-primary transition-colors duration-150"
              >
                View Full Report on {result.serviceName} <LinkIcon className="w-3 h-3 ml-1" />
              </a>
            )}
          </>
        );
      default:
        return <p className="text-xs text-slate-400">Status: {result.status}.</p>;
    }
  };

  return (
    <div className={`p-3 rounded-md border ${severityStyles.border} bg-slate-700/70 hover:bg-slate-700 transition-all shadow-md`}>
      <h4 className="text-base font-semibold text-slate-100 mb-2 border-b border-slate-600 pb-1.5">{result.serviceName}</h4>
      {renderStatusSpecificContent()}
    </div>
  );
};


const IpResultCard: React.FC<IpResultCardProps> = ({ scanData }) => {
  const overallSeverity = scanData.isScanning ? Severity.UNKNOWN : scanData.overallSeverity;
  const overallSeverityStyles = SEVERITY_COLORS[overallSeverity];

  if (scanData.isScanning && !scanData.results.some(r => r.status !== 'pending')) { // If truly initial scan
    return (
      <div className="p-4 bg-slate-700 rounded-lg shadow-md border border-slate-600">
        <div className="flex justify-between items-center mb-2">
            <h3 className="text-lg font-semibold text-primary-light break-all">{scanData.ip}</h3>
        </div>
        <LoadingSpinner text={`Initiating scans for ${scanData.ip}...`} />
      </div>
    );
  }
  
  if (scanData.error) {
     return (
      <div className={`p-4 bg-red-900 bg-opacity-30 rounded-lg shadow-md border ${SEVERITY_COLORS[Severity.MALICIOUS].border}`}>
        <h3 className="text-lg font-semibold text-red-300 break-all">{scanData.ip}</h3>
        <p className="text-sm text-red-200 mt-1">{scanData.error}</p>
      </div>
    );
  }

  return (
    <div className={`p-4 bg-slate-800 rounded-lg shadow-xl border ${overallSeverityStyles.border} transition-shadow hover:shadow-primary-dark/30`}>
      <div className="flex flex-col sm:flex-row justify-between sm:items-center mb-3 pb-3 border-b border-slate-700">
        <h3 className="text-xl font-bold text-slate-100 break-all mb-2 sm:mb-0">{scanData.ip}</h3>
        {!scanData.isScanning && (
          <div className={`flex items-center px-3 py-1 rounded-full text-sm font-medium ${overallSeverityStyles.bg} ${overallSeverityStyles.text}`}>
            <SeverityIcon severity={overallSeverity} className="w-5 h-5 mr-0" />
            Overall: {overallSeverity}
          </div>
        )}
         {scanData.isScanning && (
          <div className="flex items-center text-sm text-primary-light">
            <LoadingSpinner size="sm" />
            <span className="ml-2">Scanning...</span>
          </div>
        )}
      </div>
      
      {scanData.results.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scanData.results.map(result => (
            <ServiceResultDisplay key={`${scanData.id}-${result.serviceName}`} result={result} />
          ))}
        </div>
      ) : (
        <p className="text-slate-400 text-center py-4">No scan results available for this IP.</p>
      )}
    </div>
  );
};

export default IpResultCard;