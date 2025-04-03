import { useState } from 'react';

export function useTerminal() {
  const [logs, setLogs] = useState<string[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  
  const clearLogs = () => {
    setLogs([]);
  };
  
  const addLog = (log: string) => {
    setLogs(prev => [...prev, log]);
  };
  
  const addLogs = (newLogs: string[]) => {
    setLogs(prev => [...prev, ...newLogs]);
  };
  
  return {
    logs,
    isRunning,
    setIsRunning,
    clearLogs,
    addLog,
    addLogs
  };
}
