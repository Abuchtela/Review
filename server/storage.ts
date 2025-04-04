import { users, vulnerabilities, type User, type InsertUser, type Vulnerability, type InsertVulnerability } from "@shared/schema";

export interface IStorage {
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // Vulnerability operations
  getAllVulnerabilities(): Promise<Vulnerability[]>;
  getVulnerabilityById(id: string): Promise<Vulnerability | undefined>;
  createVulnerability(vulnerability: InsertVulnerability): Promise<Vulnerability>;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private vulnerabilities: Map<string, Vulnerability>;
  currentId: number;

  constructor() {
    this.users = new Map();
    this.vulnerabilities = new Map();
    this.currentId = 1;
    this.initializeVulnerabilities();
  }

  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentId++;
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }
  
  async getAllVulnerabilities(): Promise<Vulnerability[]> {
    return Array.from(this.vulnerabilities.values());
  }
  
  async getVulnerabilityById(id: string): Promise<Vulnerability | undefined> {
    return this.vulnerabilities.get(id);
  }
  
  async createVulnerability(vulnerability: InsertVulnerability): Promise<Vulnerability> {
    this.vulnerabilities.set(vulnerability.id, vulnerability as Vulnerability);
    return vulnerability as Vulnerability;
  }
  
  private initializeVulnerabilities() {
    // Create basic vulnerability data for the server API
    // The frontend has the complete data
    [
      {
        id: "cross-layer-reentrancy",
        title: "Cross-Layer Reentrancy",
        severity: "critical",
        description: "Message passing between L1 and L2 can create complex reentrancy vulnerabilities specific to Optimism's architecture.",
        attackVector: ["Malicious contract interactions"],
        affectedContracts: ["L1CrossDomainMessenger"]
      },
      {
        id: "direct-fund-theft",
        title: "Direct Fund Theft in Bridging Contracts",
        severity: "critical",
        description: "Vulnerability allows an attacker to directly steal user funds from the contract due to missing authentication.",
        attackVector: ["Unauthorized withdrawals"],
        affectedContracts: ["L1StandardBridge"]
      },
      {
        id: "missing-state-root-verification",
        title: "Missing State Root Verification",
        severity: "critical",
        description: "A critical vulnerability in Optimism's withdrawal system where the OptimismPortal doesn't properly verify withdrawal proofs.",
        attackVector: ["Fraudulent withdrawals"],
        affectedContracts: ["OptimismPortal"]
      }
    ].forEach(vuln => {
      this.vulnerabilities.set(vuln.id, vuln as Vulnerability);
    });
  }
}

export const storage = new MemStorage();
