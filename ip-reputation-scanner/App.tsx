import React, { useState, useEffect } from 'react';
import ApiKeyManager from './components/ApiKeyManager';
import IpScanner from './components/IpScanner';
import TabsComponent from './components/TabsComponent';
import { AppTab } from './types';
import { ShieldCheckIcon, KeyIcon, CloudArrowUpIcon, ShieldExclamationIcon as LockIcon } from './components/Icons';
import LoadingSpinner from './components/LoadingSpinner'; // For IP check loading

// !!! IMPORTANT: This IP address is now set to allow access only from 106.51.108.122 !!!
// If you need to allow other IPs, you must add them to this array.
const ALLOWED_IPS: string[] = ['106.51.108.122', '122.179.31.176'];

type IpCheckStatus = 'checking' | 'allowed' | 'denied' | 'error';

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<AppTab>(AppTab.IP_SCANNER);
  const [ipCheckStatus, setIpCheckStatus] = useState<IpCheckStatus>('checking');
  const [accessDeniedReason, setAccessDeniedReason] = useState<string>('');
  const [clientIpDisplay, setClientIpDisplay] = useState<string | null>(null);

  useEffect(() => {
    const verifyIpAccess = async () => {
      try {
        const response = await fetch('https://api.ipify.org?format=json');
        if (!response.ok) {
          throw new Error(`IP lookup failed with status: ${response.status}`);
        }
        const data = await response.json();
        const clientIp = data.ip;
        setClientIpDisplay(clientIp);

        if (ALLOWED_IPS.includes(clientIp)) {
          setIpCheckStatus('allowed');
        } else {
          setIpCheckStatus('denied');
          setAccessDeniedReason(`Your IP address (${clientIp}) is not authorized to access this application.`);
        }
      } catch (error: any) {
        console.error('IP address verification failed:', error);
        setIpCheckStatus('error');
        setAccessDeniedReason(`Could not verify your IP address. Access denied. (${error.message || 'Unknown error'})`);
      }
    };

    // Check if running on localhost for development, bypass check if so.
    // This allows easier local development without needing to add 127.0.0.1 or local network IPs.
    if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
        console.warn("Development mode: IP check bypassed for localhost.");
        setIpCheckStatus('allowed');
    } else {
        verifyIpAccess();
    }
  }, []);

  const tabs = [
    { id: AppTab.IP_SCANNER, label: 'IP Scanner', icon: <CloudArrowUpIcon className="w-5 h-5 mr-2" /> },
    { id: AppTab.API_KEYS, label: 'API Keys', icon: <KeyIcon className="w-5 h-5 mr-2" /> },
  ];

  if (ipCheckStatus === 'checking') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex flex-col items-center justify-center p-4 text-gray-100">
        <LoadingSpinner size="lg" text="Verifying access..." />
        <p className="mt-4 text-slate-400 text-sm">Checking your IP address against the authorized list.</p>
      </div>
    );
  }

  if (ipCheckStatus === 'denied' || ipCheckStatus === 'error') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex flex-col items-center justify-center p-4 text-gray-100">
        <div className="bg-slate-800 shadow-2xl rounded-lg p-8 w-full max-w-lg text-center">
          <LockIcon className="w-20 h-20 text-red-500 mx-auto mb-6" />
          <h2 className="text-3xl font-bold text-slate-100 mb-3">Access Denied</h2>
          <p className="text-slate-300 mb-6 text-md">{accessDeniedReason}</p>
          {clientIpDisplay && ipCheckStatus === 'denied' && (
            <p className="text-xs text-slate-500">
              Detected IP: {clientIpDisplay}. This IP is not in the allowed list: [{ALLOWED_IPS.join(', ')}].
            </p>
          )}
           <p className="mt-6 text-xs text-slate-500">
            This is a client-side IP check. For robust security, configure IP restrictions at your hosting provider (e.g., Render).
            If you believe this is an error, please ensure your current public IP address is included in the `ALLOWED_IPS` list within the application code by the administrator.
          </p>
        </div>
      </div>
    );
  }

  // Render main application if ipCheckStatus === 'allowed'
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-gray-100 p-4 sm:p-6 lg:p-8">
      <header className="mb-8 text-center">
        <div className="inline-flex items-center bg-slate-700 p-3 rounded-lg shadow-lg">
          <ShieldCheckIcon className="w-12 h-12 text-primary-light" />
          <h1 className="text-4xl font-bold ml-4 tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-primary-light to-secondary">
            IP Reputation Scanner
          </h1>
        </div>
        <p className="mt-2 text-slate-400 text-lg">
          Analyze IP addresses using multiple threat intelligence services.
        </p>
      </header>

      <main className="max-w-5xl mx-auto bg-slate-800 shadow-2xl rounded-lg p-6">
        <TabsComponent tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />
        <div className="mt-6">
          {activeTab === AppTab.IP_SCANNER && <IpScanner />}
          {activeTab === AppTab.API_KEYS && <ApiKeyManager />}
        </div>
      </main>

      <footer className="text-center mt-12 text-slate-500 text-sm">
        <p>&copy; {new Date().getFullYear()} IP Reputation Scanner. All rights reserved.</p>
        <p className="mt-1">Ensure compliance with API provider terms of service.</p>
      </footer>
    </div>
  );
};

export default App;
