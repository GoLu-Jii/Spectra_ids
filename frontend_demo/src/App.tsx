import React from 'react';
import { SpectraBoot } from './components/boot/SpectraBoot';
import { DashboardShell } from './components/layout/DashboardShell';
import { SpectraProvider, useSpectra } from './context/SpectraContext';

const MainAppContent: React.FC = () => {
  const { bootComplete, setBootComplete } = useSpectra();

  if (!bootComplete) {
    return <SpectraBoot onComplete={() => setBootComplete(true)} />;
  }

  return <DashboardShell />;
};

export function App() {
  return (
    <SpectraProvider>
      <MainAppContent />
    </SpectraProvider>
  );
}

export default App;
