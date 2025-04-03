import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import path from "path";
import { execSync, exec } from "child_process";
import fs from "fs";

export async function registerRoutes(app: Express): Promise<Server> {
  // API Routes
  
  // Get list of all vulnerabilities
  app.get('/api/vulnerabilities', async (req, res) => {
    try {
      const vulnerabilities = await storage.getAllVulnerabilities();
      res.json(vulnerabilities);
    } catch (error) {
      console.error('Error fetching vulnerabilities:', error);
      res.status(500).json({ error: 'Failed to fetch vulnerabilities' });
    }
  });

  // Get specific vulnerability details
  app.get('/api/vulnerabilities/:id', async (req, res) => {
    try {
      const vulnerability = await storage.getVulnerabilityById(req.params.id);
      
      if (!vulnerability) {
        return res.status(404).json({ error: 'Vulnerability not found' });
      }
      
      res.json(vulnerability);
    } catch (error) {
      console.error('Error fetching vulnerability:', error);
      res.status(500).json({ error: 'Failed to fetch vulnerability details' });
    }
  });

  // Compile contract for a specific vulnerability
  app.post('/api/contracts/compile/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
      // Get the vulnerability to determine which contracts to compile
      const vulnerability = await storage.getVulnerabilityById(id);
      
      if (!vulnerability) {
        return res.status(404).json({ error: 'Vulnerability not found' });
      }
      
      // Compile the contracts
      const compilationResult = await compileVulnerabilityContracts(id);
      
      res.json(compilationResult);
    } catch (error) {
      console.error('Error compiling contracts:', error);
      res.status(500).json({ 
        success: false, 
        output: error instanceof Error ? error.message : 'Unknown compilation error' 
      });
    }
  });

  // Run exploit for a specific vulnerability
  app.post('/api/exploits/run/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
      // Get the vulnerability
      const vulnerability = await storage.getVulnerabilityById(id);
      
      if (!vulnerability) {
        return res.status(404).json({ error: 'Vulnerability not found' });
      }
      
      // Run the exploit
      const exploitResult = await runExploit(id);
      
      res.json(exploitResult);
    } catch (error) {
      console.error('Error running exploit:', error);
      res.status(500).json({ 
        success: false, 
        logs: [`Error: ${error instanceof Error ? error.message : 'Unknown error'}`]
      });
    }
  });

  // Reset the environment
  app.post('/api/environment/reset', async (req, res) => {
    try {
      // Reset the hardhat environment
      await resetEnvironment();
      
      res.json({ success: true });
    } catch (error) {
      console.error('Error resetting environment:', error);
      res.status(500).json({ error: 'Failed to reset environment' });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}

// Helper functions

async function compileVulnerabilityContracts(vulnerabilityId: string): Promise<CompilationResult> {
  try {
    // Execute the compile script with the vulnerability ID
    const output = execSync(`npx hardhat compile --config ./server/hardhat/hardhat.config.ts`, {
      cwd: process.cwd(),
      env: { ...process.env, VULNERABILITY_ID: vulnerabilityId }
    }).toString();
    
    return {
      success: true,
      output
    };
  } catch (error) {
    console.error('Compilation error:', error);
    return {
      success: false,
      output: error instanceof Error ? error.message : 'Unknown compilation error'
    };
  }
}

async function runExploit(vulnerabilityId: string): Promise<{ success: boolean, logs: string[] }> {
  try {
    // Execute the exploit script for the specified vulnerability
    const output = execSync(`npx hardhat run ./server/hardhat/scripts/run-exploit.ts --config ./server/hardhat/hardhat.config.ts --network localhost`, {
      cwd: process.cwd(),
      env: { ...process.env, VULNERABILITY_ID: vulnerabilityId }
    }).toString();
    
    // Split output into lines for the logs
    const logs = output.split('\n').filter(line => line.trim() !== '');
    
    return {
      success: true,
      logs
    };
  } catch (error) {
    console.error('Exploit execution error:', error);
    let errorOutput = '';
    
    if (error instanceof Error) {
      errorOutput = error.message;
    } else {
      errorOutput = 'Unknown error during exploit execution';
    }
    
    return {
      success: false,
      logs: [`Error executing exploit: ${errorOutput}`]
    };
  }
}

async function resetEnvironment(): Promise<void> {
  try {
    // Reset hardhat node
    execSync(`npx hardhat clean --config ./server/hardhat/hardhat.config.ts`, {
      cwd: process.cwd()
    });
    
    return Promise.resolve();
  } catch (error) {
    console.error('Environment reset error:', error);
    return Promise.reject(error);
  }
}
