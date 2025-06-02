import React, { useState, useCallback, ChangeEvent, useEffect } from 'react';
import { useApiKeys } from '../contexts/ApiKeyContext';
import { scanIpConcurrently } from '../services/ipScanCoordinator';
import { AggregatedScanResult, ApiName, Severity, ScanMode, IpInputMode, ServiceScanResult } from '../types';
import IpResultCard from './IpResultCard';
import LoadingSpinner from './LoadingSpinner';
import { CloudArrowUpIcon, DocumentTextIcon, TrashIcon, DownloadIcon, ListBulletIcon, DocumentPlusIcon } from './Icons';
import { generateHtmlReport } from '../utils/reportGenerator';
import { LOCAL_STORAGE_SCAN_HISTORY_KEY } from '../constants';


const IpScanner: React.FC = () => {
  const { apiKeys, isLoading: apiKeysLoading, getApiKeysForService } = useApiKeys();
  const [scanHistory, setScanHistory] = useState<AggregatedScanResult[]>(() => {
    try {
      const storedHistory = localStorage.getItem(LOCAL_STORAGE_SCAN_HISTORY_KEY);
      return storedHistory ? JSON.parse(storedHistory) : [];
    } catch (e) {
      console.error("Error loading scan history from localStorage:", e);
      return [];
    }
  });
  const [isScanningGlobal, setIsScanningGlobal] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [manualIpInput, setManualIpInput] = useState<string>('');
  const [currentInputMode, setCurrentInputMode] = useState<IpInputMode>(IpInputMode.FILE_UPLOAD);
  const [enableSmartScan, setEnableSmartScan] = useState<boolean>(true);

  useEffect(() => {
    try {
      localStorage.setItem(LOCAL_STORAGE_SCAN_HISTORY_KEY, JSON.stringify(scanHistory));
    } catch (e) {
      console.error("Error saving scan history to localStorage:", e);
    }
  }, [scanHistory]);
  
  const createInitialPendingScan = (ip: string): AggregatedScanResult => {
    const id = `${Date.now()}-${ip.replace(/\./g, '-')}-${Math.random().toString(36).substring(2, 7)}`;
    return {
      id, ip,
      results: Object.values(ApiName).map(name => ({
        serviceName: name, ip, status: 'pending', severity: Severity.UNKNOWN,
      })),
      overallSeverity: Severity.UNKNOWN, isScanning: true,
    };
  };
  
  const handleSingleServiceUpdate = useCallback((updatedServiceResult: ServiceScanResult) => {
    setScanHistory(prevHistory => {
      return prevHistory.map(scan => {
        // Match by IP, as scan ID might not be set yet if this is the very first update for an IP
        if (scan.ip === updatedServiceResult.ip && scan.isScanning) { 
          const updatedResults = scan.results.map(r =>
            r.serviceName === updatedServiceResult.serviceName ? updatedServiceResult : r
          );
          return {
            ...scan,
            results: updatedResults,
          };
        }
        return scan;
      });
    });
  }, []);


  const processAndScanInputs = useCallback(async () => {
    if (apiKeysLoading) {
      setFileError('API keys are still loading, please wait.');
      return;
    }

    let rawIps: string[] = [];
    setFileError(null);

    if (currentInputMode === IpInputMode.FILE_UPLOAD) {
      if (!selectedFile) {
        setFileError('Please select a file first.');
        return;
      }
      const text = await selectedFile.text().catch(() => {
        setFileError('Error reading file.');
        return null;
      });
      if (!text) return;
      const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
      rawIps = Array.from(new Set(text.match(ipRegex) || []));
    } else { // Manual Entry
      if (!manualIpInput.trim()) {
        setFileError('Please enter IP addresses.');
        return;
      }
      const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
      rawIps = Array.from(new Set(manualIpInput.match(ipRegex) || []));
    }

    if (rawIps.length === 0) {
      setFileError('No valid IP addresses found.');
      return;
    }

    // Filter out IPs that are already in scanHistory and are NOT marked with a recoverable error or stuck pending.
    // For simplicity now: only scan IPs not present in history at all.
    // Or if present, ensure it's not currently scanning. If completed, don't re-scan automatically.
    const ipsToScan = rawIps.filter(ip => {
        const existingScan = scanHistory.find(sh => sh.ip === ip);
        if (existingScan) {
            // Do not re-scan if it's currently scanning OR if it has completed without a major error.
            // A "major error" could be a specific flag, or just if `existingScan.error` is set.
            // For now, to prevent re-scanning completed entries:
            return existingScan.isScanning; // If it was stuck scanning, allow re-queue. Otherwise, if false, don't scan.
                                            // This means if isScanning is false (completed), it won't be re-added.
                                            // A better way: only scan if NOT in history, or allow explicit re-scan.
                                            // Let's change to: Only scan if IP is not in history AT ALL.
        }
        return true; // Not in history, so scan it.
    }).filter(ip => !scanHistory.some(sh => sh.ip === ip)); // Simplest: only scan IPs not in history.

    if (ipsToScan.length === 0) {
      if (rawIps.length > 0) {
        setFileError('All submitted IPs have already been scanned or are being processed. Clear results to scan again.');
      } else {
        setFileError('No new IP addresses to scan.');
      }
      return;
    }
    
    setIsScanningGlobal(true);

    const newPendingScans = ipsToScan.map(ip => createInitialPendingScan(ip));

    setScanHistory(prev => {
        // Add new pending scans to the top, ensuring no duplicates by ID if somehow re-triggered quickly.
        const currentIds = new Set(prev.map(p => p.id));
        const trulyNewPendingScans = newPendingScans.filter(ns => !currentIds.has(ns.id));
        return [...trulyNewPendingScans, ...prev].sort((a, b) => parseInt(b.id.split('-')[0]) - parseInt(a.id.split('-')[0]));
    });
    

    const scanPromises = newPendingScans.map(pendingScan => {
      return scanIpConcurrently(pendingScan.ip, apiKeys, pendingScan.id, enableSmartScan ? ScanMode.SMART : ScanMode.FULL, handleSingleServiceUpdate)
        .then(finalResultForIp => {
          setScanHistory(prev => prev.map(sh => sh.id === finalResultForIp.id ? finalResultForIp : sh));
        })
        .catch(error => {
          console.error(`Unhandled error scanning IP ${pendingScan.ip}:`, error);
          const errorResult: AggregatedScanResult = {
            id: pendingScan.id, ip: pendingScan.ip, results: [],
            overallSeverity: Severity.UNKNOWN, isScanning: false,
            error: `Failed to scan IP: ${error.message || 'Unknown error'}`
          };
          setScanHistory(prev => prev.map(sh => sh.id === pendingScan.id ? errorResult : sh));
        });
    });

    await Promise.allSettled(scanPromises);
    setIsScanningGlobal(false);

  }, [selectedFile, manualIpInput, currentInputMode, apiKeys, apiKeysLoading, enableSmartScan, scanHistory, handleSingleServiceUpdate]);

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    setFileError(null);
    const file = event.target.files?.[0];
    if (file) {
      if (file.type === 'text/plain') {
        setSelectedFile(file);
        setFileName(file.name);
      } else {
        setFileError('Invalid file type. Please upload a .txt file.');
        setSelectedFile(null);
        setFileName(null);
        event.target.value = '';
      }
    } else {
      setSelectedFile(null);
      setFileName(null);
    }
  };

  const clearResults = () => {
    setScanHistory([]);
    setFileName(null);
    setSelectedFile(null);
    setManualIpInput('');
    const fileInput = document.getElementById('ipFileInput') as HTMLInputElement;
    if (fileInput) fileInput.value = '';
    localStorage.removeItem(LOCAL_STORAGE_SCAN_HISTORY_KEY);
  };

  const handleDownloadReport = () => {
    const completedScans = scanHistory.filter(sh => !sh.isScanning && !sh.error);
    if (completedScans.length === 0) return; 
    const htmlContent = generateHtmlReport(completedScans);
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ip_reputation_report_${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };
  
  const hasAnyConfiguredKeys = Object.values(ApiName).some(name => getApiKeysForService(name).length > 0);

  return (
    <div className="space-y-6">
      <div className="p-6 bg-slate-700 rounded-lg shadow-md">
        <div className="mb-4 flex items-center space-x-4">
            <span className="text-sm font-medium text-slate-300">Input Method:</span>
            <label className="flex items-center space-x-2 cursor-pointer">
                <input type="radio" name="inputMode" value={IpInputMode.FILE_UPLOAD} checked={currentInputMode === IpInputMode.FILE_UPLOAD} onChange={() => setCurrentInputMode(IpInputMode.FILE_UPLOAD)} className="form-radio text-primary focus:ring-primary-light"/>
                <span className="text-slate-200">File Upload</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
                <input type="radio" name="inputMode" value={IpInputMode.MANUAL_ENTRY} checked={currentInputMode === IpInputMode.MANUAL_ENTRY} onChange={() => setCurrentInputMode(IpInputMode.MANUAL_ENTRY)} className="form-radio text-primary focus:ring-primary-light"/>
                <span className="text-slate-200">Manual Entry</span>
            </label>
        </div>

        {currentInputMode === IpInputMode.FILE_UPLOAD && (
          <label htmlFor="ipFileInput" className="block">
            <div className={`flex items-center justify-center w-full px-4 py-3 border-2 border-dashed rounded-md cursor-pointer ${fileError ? 'border-red-500 hover:border-red-400' : 'border-slate-500 hover:border-primary-light'} bg-slate-800 hover:bg-slate-750 transition-colors`}>
              <CloudArrowUpIcon className="w-8 h-8 text-slate-400 mr-3" />
              <div className="text-sm">
                <span className="font-semibold text-primary-light">{fileName ? `Selected: ${fileName}` : 'Upload a .txt file with IP addresses'}</span>
                {!fileName && <p className="text-slate-400">Click to browse or drag & drop</p>}
              </div>
            </div>
            <input id="ipFileInput" type="file" accept=".txt" onChange={handleFileChange} className="hidden" disabled={isScanningGlobal}/>
          </label>
        )}

        {currentInputMode === IpInputMode.MANUAL_ENTRY && (
          <textarea
            value={manualIpInput}
            onChange={(e) => setManualIpInput(e.target.value)}
            placeholder="Enter IP addresses, one per line..."
            rows={4}
            className="w-full p-3 border border-slate-500 rounded bg-slate-800 text-slate-200 focus:ring-2 focus:ring-primary focus:border-primary"
            disabled={isScanningGlobal}
          />
        )}
        {fileError && <p className="mt-2 text-sm text-red-400">{fileError}</p>}

        <div className="mt-4 flex flex-col sm:flex-row justify-between items-center space-y-3 sm:space-y-0">
            <label className="flex items-center space-x-2 cursor-pointer">
                <input type="checkbox" checked={enableSmartScan} onChange={() => setEnableSmartScan(prev => !prev)} className="form-checkbox text-primary focus:ring-primary-light rounded"/>
                <span className="text-sm text-slate-200">Enable Smart Scan <span className="text-xs text-slate-400">(skip 3rd scan if 2 are risky)</span></span>
            </label>
            <button
                onClick={processAndScanInputs}
                disabled={
                    (currentInputMode === IpInputMode.FILE_UPLOAD && !selectedFile && !fileName) || // check fileName too in case file selected then unselected
                    (currentInputMode === IpInputMode.MANUAL_ENTRY && !manualIpInput.trim()) ||
                    isScanningGlobal || apiKeysLoading || !hasAnyConfiguredKeys
                }
                className="w-full sm:w-auto px-6 py-3 bg-primary hover:bg-primary-dark text-white font-semibold rounded-md shadow-sm focus:ring-2 focus:ring-primary-light focus:ring-opacity-50 disabled:bg-slate-500 disabled:cursor-not-allowed transition-all duration-150 flex items-center justify-center"
            >
                {isScanningGlobal ? <LoadingSpinner size="sm" /> : (currentInputMode === IpInputMode.FILE_UPLOAD ? <DocumentPlusIcon className="w-5 h-5 mr-2" /> : <ListBulletIcon className="w-5 h-5 mr-2" />)}
                Scan IPs
            </button>
        </div>
        {!apiKeysLoading && !hasAnyConfiguredKeys && (
            <p className="mt-3 text-sm text-yellow-400">No API keys are configured. Please add keys in the 'API Keys' tab.</p>
        )}
      </div>

      {(scanHistory.length > 0 || isScanningGlobal) && (
        <div className="flex flex-col sm:flex-row justify-end items-center space-y-2 sm:space-y-0 sm:space-x-3 mt-4">
            <button onClick={handleDownloadReport} disabled={isScanningGlobal || scanHistory.filter(sh => !sh.isScanning && !sh.error).length === 0} className="w-full sm:w-auto px-4 py-2 bg-secondary hover:bg-emerald-600 text-white font-medium rounded-md shadow-sm disabled:bg-slate-500 disabled:cursor-not-allowed transition-colors duration-150 flex items-center justify-center">
                <DownloadIcon className="w-5 h-5 mr-2" /> Download Report
            </button>
            <button onClick={clearResults} disabled={isScanningGlobal} className="w-full sm:w-auto px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-md shadow-sm disabled:bg-slate-500 disabled:cursor-not-allowed transition-colors duration-150 flex items-center justify-center">
                <TrashIcon className="w-5 h-5 mr-2" /> Clear Results
            </button>
        </div>
      )}
      
      <div className="space-y-4 mt-6">
        {scanHistory.sort((a,b) => parseInt(b.id.split('-')[0]) - parseInt(a.id.split('-')[0])).map(scanData =>
          <IpResultCard key={scanData.id} scanData={scanData} />
        )}
      </div>
       {scanHistory.length === 0 && !isScanningGlobal && !fileError && (
         <div className="text-center py-10 text-slate-500">
            <DocumentTextIcon className="w-16 h-16 mx-auto mb-4 opacity-30" />
            <p className="text-lg">No IP scans performed yet.</p>
            <p className="text-sm">Upload a .txt file or enter IPs manually and click "Scan IPs" to begin.</p>
        </div>
       )}
    </div>
  );
};

export default IpScanner;