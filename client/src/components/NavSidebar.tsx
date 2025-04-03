import { Link, useLocation } from "wouter";
import { Vulnerability } from "@/types";

interface NavSidebarProps {
  vulnerabilities: Vulnerability[];
  selectedId?: string;
}

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'bg-critical';
    case 'high':
      return 'bg-[#FF9100]';
    case 'medium':
      return 'bg-[#FFCC00]';
    case 'low':
      return 'bg-[#64DD17]';
    default:
      return 'bg-gray-500';
  }
};

const NavSidebar = ({ vulnerabilities, selectedId }: NavSidebarProps) => {
  const [location] = useLocation();

  // Group vulnerabilities by severity
  const criticalVulnerabilities = vulnerabilities.filter(v => v.severity === 'critical');
  const highVulnerabilities = vulnerabilities.filter(v => v.severity === 'high');
  const mediumVulnerabilities = vulnerabilities.filter(v => v.severity === 'medium');
  const lowVulnerabilities = vulnerabilities.filter(v => v.severity === 'low');

  const renderVulnerabilityGroup = (groupVulnerabilities: Vulnerability[], title: string) => {
    if (groupVulnerabilities.length === 0) return null;
    
    return (
      <div>
        <h3 className="text-sm uppercase text-gray-400 mb-2">{title}</h3>
        <ul className="space-y-2">
          {groupVulnerabilities.map(vulnerability => {
            const isSelected = vulnerability.id === selectedId;
            const severityColor = getSeverityColor(vulnerability.severity);
            
            return (
              <li key={vulnerability.id}>
                <Link href={`/vulnerability/${vulnerability.id}`}>
                  <a 
                    className={`w-full text-left p-2 rounded-md bg-[#242424] hover:bg-[#242424]/80 flex items-center
                      ${isSelected ? 'border border-' + vulnerability.severity + '/30' : 'border border-transparent'}`}
                  >
                    <span className={`w-2 h-2 ${severityColor} rounded-full mr-2`}></span>
                    <span>{vulnerability.title}</span>
                  </a>
                </Link>
              </li>
            );
          })}
        </ul>
      </div>
    );
  };

  return (
    <nav className="w-64 bg-[#1E1E1E] border-r border-[#333333] overflow-y-auto">
      <div className="p-4">
        <h2 className="text-lg font-medium mb-4">Vulnerabilities</h2>
        
        <div className="space-y-4">
          {renderVulnerabilityGroup(criticalVulnerabilities, 'Critical Severity')}
          {renderVulnerabilityGroup(highVulnerabilities, 'High Severity')}
          {renderVulnerabilityGroup(mediumVulnerabilities, 'Medium Severity')}
          {renderVulnerabilityGroup(lowVulnerabilities, 'Low Severity')}
        </div>
      </div>
    </nav>
  );
};

export default NavSidebar;
