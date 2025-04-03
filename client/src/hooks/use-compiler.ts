import { useState } from 'react';
import { apiRequest } from '@/lib/queryClient';
import { CompilationResult } from '@/types';

export function useCompiler() {
  const [isCompiling, setIsCompiling] = useState(false);
  
  const compileContract = async (vulnerabilityId: string): Promise<CompilationResult> => {
    setIsCompiling(true);
    
    try {
      const response = await apiRequest('POST', `/api/contracts/compile/${vulnerabilityId}`, {});
      const result = await response.json();
      return result;
    } catch (error) {
      console.error('Compilation error:', error);
      return {
        success: false,
        output: error instanceof Error ? error.message : 'Unknown compilation error'
      };
    } finally {
      setIsCompiling(false);
    }
  };
  
  return {
    isCompiling,
    compileContract
  };
}
