import React, { createContext, useState, useEffect, useContext, ReactNode } from 'react';
import { ApiKeyStore, ApiName, ApiKeyConfig } from '../types';
import { LOCAL_STORAGE_API_KEY_PREFIX } from '../constants';

interface ApiKeyContextType {
  apiKeys: ApiKeyStore;
  addApiKey: (name: ApiName, key: string, label?: string) => void;
  removeApiKey: (name: ApiName, keyId: string) => void;
  isLoading: boolean;
  getApiKeysForService: (name: ApiName) => ApiKeyConfig[];
}

const ApiKeyContext = createContext<ApiKeyContextType | undefined>(undefined);

export const ApiKeyProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [apiKeys, setApiKeys] = useState<ApiKeyStore>({});
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const loadedKeys: ApiKeyStore = {};
    Object.values(ApiName).forEach(apiName => {
      try {
        const storedKeysRaw = localStorage.getItem(`${LOCAL_STORAGE_API_KEY_PREFIX}${apiName}`);
        if (storedKeysRaw) {
          const parsedKeys = JSON.parse(storedKeysRaw) as ApiKeyConfig[];
          // Ensure all keys have an id and addedDate, for backwards compatibility if schema changes
          loadedKeys[apiName] = parsedKeys.map(k => ({
             ...k,
             id: k.id || `${Date.now()}-${Math.random().toString(36).substring(2,9)}`, // ensure id
             addedDate: k.addedDate || Date.now() // ensure addedDate
            }));
        } else {
          loadedKeys[apiName] = [];
        }
      } catch (error) {
        console.error(`Error loading API keys for ${apiName} from localStorage:`, error);
        loadedKeys[apiName] = [];
      }
    });
    setApiKeys(loadedKeys);
    setIsLoading(false);
  }, []);

  const saveKeysToLocalStorage = (name: ApiName, keys: ApiKeyConfig[]) => {
    try {
      localStorage.setItem(`${LOCAL_STORAGE_API_KEY_PREFIX}${name}`, JSON.stringify(keys));
    } catch (error) {
      console.error(`Error saving API keys for ${name} to localStorage:`, error);
    }
  };

  const addApiKey = (name: ApiName, key: string, label?: string) => {
    setApiKeys(prev => {
      const existingKeys = prev[name] || [];
      const newKey: ApiKeyConfig = { 
        id: `${Date.now()}-${Math.random().toString(36).substring(2,9)}`, 
        key, 
        label,
        addedDate: Date.now()
      };
      const updatedKeys = [...existingKeys, newKey];
      saveKeysToLocalStorage(name, updatedKeys);
      return { ...prev, [name]: updatedKeys };
    });
  };

  const removeApiKey = (name: ApiName, keyId: string) => {
     setApiKeys(prev => {
      const existingKeys = prev[name] || [];
      const updatedKeys = existingKeys.filter(k => k.id !== keyId);
      saveKeysToLocalStorage(name, updatedKeys);
      return { ...prev, [name]: updatedKeys };
    });
  };

  const getApiKeysForService = (name: ApiName): ApiKeyConfig[] => {
    return apiKeys[name] || [];
  };


  return (
    <ApiKeyContext.Provider value={{ apiKeys, addApiKey, removeApiKey, isLoading, getApiKeysForService }}>
      {children}
    </ApiKeyContext.Provider>
  );
};

export const useApiKeys = (): ApiKeyContextType => {
  const context = useContext(ApiKeyContext);
  if (!context) {
    throw new Error('useApiKeys must be used within an ApiKeyProvider');
  }
  return context;
};