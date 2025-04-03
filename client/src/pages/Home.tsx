import { useState, useEffect } from "react";
import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Vulnerability } from "@/types";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";

const Home = () => {
  const { toast } = useToast();
  const { data: vulnerabilities = [], isLoading, error } = useQuery<Vulnerability[]>({
    queryKey: ['/api/vulnerabilities'],
  });

  useEffect(() => {
    if (error) {
      toast({
        title: "Error loading vulnerabilities",
        description: "Failed to load vulnerability data. Please try refreshing the page.",
        variant: "destructive",
      });
    }
  }, [error, toast]);

  const criticalVulnerabilities = vulnerabilities.filter(v => v.severity === 'critical');
  const highVulnerabilities = vulnerabilities.filter(v => v.severity === 'high');
  const mediumVulnerabilities = vulnerabilities.filter(v => v.severity === 'medium');
  
  if (isLoading) {
    return (
      <div className="h-screen flex flex-col bg-[#121212]">
        <header className="bg-[#1E1E1E] border-b border-[#333333] p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <img src="https://www.optimism.io/static/images/logos/logo-icon-red.svg" alt="Optimism Logo" className="h-8 w-8" />
              <h1 className="text-xl font-semibold">Optimism Security Exploit Lab</h1>
            </div>
          </div>
        </header>
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-500 mx-auto"></div>
            <p className="mt-4 text-gray-400">Loading vulnerability data...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-[#121212]">
      <header className="bg-[#1E1E1E] border-b border-[#333333] p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <img src="https://www.optimism.io/static/images/logos/logo-icon-red.svg" alt="Optimism Logo" className="h-8 w-8" />
            <h1 className="text-xl font-semibold">Optimism Security Exploit Lab</h1>
          </div>
        </div>
      </header>

      <main className="flex-1 overflow-y-auto p-6">
        <div className="max-w-5xl mx-auto">
          <div className="mb-8">
            <h2 className="text-2xl font-bold mb-4">Optimism Security Vulnerabilities</h2>
            <p className="text-gray-400 mb-6">
              This lab environment allows you to explore, understand, and test exploits for various security vulnerabilities found in Optimism's cross-domain messaging system. Select a vulnerability to view details and run exploit demonstrations.
            </p>

            <h3 className="text-xl font-semibold mb-4 text-critical">Critical Vulnerabilities</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
              {criticalVulnerabilities.map(vulnerability => (
                <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} />
              ))}
            </div>

            <h3 className="text-xl font-semibold mb-4 text-[#FF9100]">High Severity Vulnerabilities</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
              {highVulnerabilities.map(vulnerability => (
                <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} />
              ))}
            </div>

            <h3 className="text-xl font-semibold mb-4 text-[#FFCC00]">Medium Severity Vulnerabilities</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {mediumVulnerabilities.map(vulnerability => (
                <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} />
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

const VulnerabilityCard = ({ vulnerability }: { vulnerability: Vulnerability }) => {
  const severityColors = {
    critical: 'border-critical bg-critical/10',
    high: 'border-[#FF9100] bg-[#FF9100]/10',
    medium: 'border-[#FFCC00] bg-[#FFCC00]/10',
    low: 'border-[#64DD17] bg-[#64DD17]/10'
  };

  const borderColor = severityColors[vulnerability.severity] || 'border-gray-700 bg-gray-800/50';

  return (
    <Link href={`/vulnerability/${vulnerability.id}`}>
      <a className={`block border ${borderColor} rounded-lg overflow-hidden hover:shadow-md transition-shadow`}>
        <Card className="bg-transparent border-0">
          <CardContent className="p-4">
            <div className="flex items-center mb-2">
              <h3 className="text-lg font-medium">{vulnerability.title}</h3>
            </div>
            <p className="text-sm text-gray-400 mb-3 line-clamp-2">{vulnerability.description}</p>
            <Separator className="my-3 bg-gray-700" />
            <div className="flex justify-between text-xs">
              <span className="uppercase font-semibold">{vulnerability.severity}</span>
              <span>{vulnerability.affectedContracts.length} contract{vulnerability.affectedContracts.length !== 1 ? 's' : ''}</span>
            </div>
          </CardContent>
        </Card>
      </a>
    </Link>
  );
};

export default Home;
