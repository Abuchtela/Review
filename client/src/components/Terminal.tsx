import { useEffect, useRef } from "react";

interface TerminalProps {
  logs: string[];
}

const Terminal = ({ logs }: TerminalProps) => {
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  const formatLine = (line: string) => {
    // Check for success/error indicators
    if (line.includes("✅") || line.includes("SUCCESSFUL")) {
      return <span className="text-green-500">{line}</span>;
    } else if (line.includes("❌") || line.includes("FAILED") || line.includes("Error")) {
      return <span className="text-red-500">{line}</span>;
    } else if (line.startsWith(">")) {
      return <span className="text-blue-400">{line}</span>;
    }
    
    return line;
  };

  // Default content if no logs
  if (logs.length === 0) {
    return (
      <div 
        ref={terminalRef}
        className="bg-black text-green-500 p-4 font-mono text-sm rounded-md h-64 overflow-auto"
      >
        &gt; Exploit lab terminal ready. Compile and run an exploit to see results.
      </div>
    );
  }

  return (
    <div 
      ref={terminalRef}
      className="bg-black text-green-500 p-4 font-mono text-sm rounded-md h-64 overflow-auto"
    >
      {logs.map((log, index) => (
        <div key={index}>
          {formatLine(log)}
          <br />
        </div>
      ))}
    </div>
  );
};

export default Terminal;
