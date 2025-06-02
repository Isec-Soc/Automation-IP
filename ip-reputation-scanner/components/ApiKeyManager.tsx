import React, { useState } from 'react';
import { useApiKeys } from '../contexts/ApiKeyContext';
import { ApiName, ApiKeyConfig } from '../types';
import { KeyIcon, EyeIcon, EyeSlashIcon, TrashIcon, CheckCircleIcon } from './Icons';

interface NewKeyInput {
  key: string;
  label: string;
}

const ApiKeyManager: React.FC = () => {
  const { apiKeys, addApiKey, removeApiKey, isLoading, getApiKeysForService } = useApiKeys();
  const [newKeyInputs, setNewKeyInputs] = useState<Partial<Record<ApiName, NewKeyInput>>>({});
  const [showKey, setShowKey] = useState<Record<string, boolean>>({}); // key is ApiKeyConfig.id
  const [feedback, setFeedback] = useState<Partial<Record<ApiName, string>>>({});


  const handleInputChange = (name: ApiName, field: keyof NewKeyInput, value: string) => {
    setNewKeyInputs(prev => ({
      ...prev,
      [name]: {
        ...(prev[name] || { key: '', label: '' }),
        [field]: value,
      },
    }));
  };

  const handleAddKey = (name: ApiName) => {
    const input = newKeyInputs[name];
    if (input && input.key) {
      addApiKey(name, input.key, input.label || undefined);
      setNewKeyInputs(prev => ({
        ...prev,
        [name]: { key: '', label: '' },
      }));
      setFeedback(prev => ({ ...prev, [name]: `API Key added for ${name}!`}));
      setTimeout(() => setFeedback(prev => ({...prev, [name]: ''})), 3000);
    }
  };

  const handleRemoveKey = (name: ApiName, keyId: string) => {
    removeApiKey(name, keyId);
  };

  const toggleShowKey = (keyId: string) => {
    setShowKey(prev => ({ ...prev, [keyId]: !prev[keyId] }));
  };

  if (isLoading) {
    return <div className="text-center p-4 text-slate-300">Loading API keys...</div>;
  }

  return (
    <div className="space-y-8 p-4 bg-slate-700 rounded-lg shadow-md">
      <h2 className="text-2xl font-semibold text-slate-100 flex items-center">
        <KeyIcon className="w-6 h-6 mr-3 text-primary-light" />
        Manage API Keys
      </h2>
      <p className="text-sm text-slate-400">
        API keys are stored locally in your browser's local storage. They are not sent to any server other than the respective API providers during scans. You can add multiple keys per service for fallback.
      </p>
      {Object.values(ApiName).map(apiName => {
        const serviceKeys = getApiKeysForService(apiName);
        return (
          <div key={apiName} className="p-4 border border-slate-600 rounded-md space-y-4 bg-slate-750 shadow">
            <h3 className="text-lg font-medium text-slate-200">{apiName}</h3>
            
            {serviceKeys.length > 0 ? (
              <div className="space-y-3">
                <p className="text-xs text-slate-400">Stored Keys ({serviceKeys.length}):</p>
                {serviceKeys.slice().sort((a,b) => b.addedDate - a.addedDate).map((apiKeyConfig) => (
                  <div key={apiKeyConfig.id} className="p-2 bg-slate-600 rounded shadow-sm">
                    <div className="flex items-center justify-between">
                      <div className="flex-grow mr-2">
                        {apiKeyConfig.label && <p className="text-xs text-slate-300 font-semibold">{apiKeyConfig.label}</p>}
                        <span className="text-sm text-slate-300 font-mono break-all">
                          {showKey[apiKeyConfig.id] ? apiKeyConfig.key : `${apiKeyConfig.key.substring(0, 4)}...${apiKeyConfig.key.slice(-4)}`}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2 flex-shrink-0">
                        <button
                          onClick={() => toggleShowKey(apiKeyConfig.id)}
                          className="p-1 text-slate-400 hover:text-primary-light focus:outline-none"
                          title={showKey[apiKeyConfig.id] ? 'Hide API Key' : 'Show API Key'}
                        >
                          {showKey[apiKeyConfig.id] ? <EyeSlashIcon className="w-5 h-5" /> : <EyeIcon className="w-5 h-5" />}
                        </button>
                        <button
                          onClick={() => handleRemoveKey(apiName, apiKeyConfig.id)}
                          className="p-1 text-red-400 hover:text-red-300 focus:outline-none"
                          title="Remove API Key"
                        >
                          <TrashIcon className="w-5 h-5" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-yellow-400">No API Keys set for {apiName}.</p>
            )}

            <div className="pt-3 border-t border-slate-600 space-y-2">
              <h4 className="text-md font-medium text-slate-300">Add New Key for {apiName}</h4>
              <input
                type="text"
                value={newKeyInputs[apiName]?.label || ''}
                onChange={e => handleInputChange(apiName, 'label', e.target.value)}
                placeholder="Optional: Label (e.g., 'Personal Key')"
                className="w-full p-2 border border-slate-500 rounded bg-slate-800 text-slate-200 focus:ring-2 focus:ring-primary focus:border-primary"
              />
              <input
                type="password" // Keep as password to obscure input
                value={newKeyInputs[apiName]?.key || ''}
                onChange={e => handleInputChange(apiName, 'key', e.target.value)}
                placeholder={`Enter ${apiName} API Key`}
                className="w-full p-2 border border-slate-500 rounded bg-slate-800 text-slate-200 focus:ring-2 focus:ring-primary focus:border-primary"
              />
              <button
                onClick={() => handleAddKey(apiName)}
                disabled={!newKeyInputs[apiName]?.key}
                className="w-full sm:w-auto px-4 py-2 bg-primary hover:bg-primary-dark text-white font-medium rounded shadow-sm disabled:bg-slate-500 disabled:cursor-not-allowed transition-colors duration-150"
              >
                Add Key
              </button>
              {feedback[apiName] && (
                <p className="text-xs text-green-400 flex items-center mt-1">
                  <CheckCircleIcon className="w-4 h-4 mr-1" /> {feedback[apiName]}
                </p>
              )}
            </div>
          </div>
        );
      })}
      <div className="mt-6 p-3 bg-slate-750 border border-yellow-600 rounded-md">
        <p className="text-yellow-300 text-sm font-medium">Important Security Note:</p>
        <p className="text-yellow-400 text-xs mt-1">
          API keys provide access to services that may have costs or quotas. Keep them secure. This application stores keys in your browser's local storage, which is vulnerable to cross-site scripting (XSS) attacks if other browser extensions or scripts are malicious. Use with caution and preferably in a secure browser environment.
        </p>
      </div>
    </div>
  );
};

export default ApiKeyManager;