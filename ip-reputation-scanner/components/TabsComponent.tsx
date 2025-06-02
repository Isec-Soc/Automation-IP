
import React from 'react';
import { AppTab } from '../types';

interface TabInfo {
  id: AppTab;
  label: string;
  icon?: React.ReactNode;
}

interface TabsComponentProps {
  tabs: TabInfo[];
  activeTab: AppTab;
  onTabChange: (tabId: AppTab) => void;
}

const TabsComponent: React.FC<TabsComponentProps> = ({ tabs, activeTab, onTabChange }) => {
  return (
    <div className="border-b border-slate-700">
      <nav className="-mb-px flex space-x-4 sm:space-x-8" aria-label="Tabs">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`
              ${
                activeTab === tab.id
                  ? 'border-primary text-primary-light'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-500'
              }
              group inline-flex items-center py-3 px-1 border-b-2 font-medium text-sm transition-colors duration-150 focus:outline-none
            `}
            aria-current={activeTab === tab.id ? 'page' : undefined}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </nav>
    </div>
  );
};

export default TabsComponent;
