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
      },
      {
        id: "incorrect-dispute-game-resolution",
        title: "Incorrect Dispute Game Resolution",
        severity: "high",
        description: "Fault dispute games can be incorrectly resolved due to improper handling of edge cases in game depth calculations.",
        attackVector: ["Edge case manipulation"],
        affectedContracts: ["FaultDisputeGame"]
      },
      {
        id: "permanent-fund-freezing",
        title: "Permanent Fund Freezing",
        severity: "high",
        description: "Funds can be permanently locked in the OptimismPortal due to missing recovery mechanisms.",
        attackVector: ["Contract locking attack"],
        affectedContracts: ["OptimismPortal"]
      },
      {
        id: "ecrecover-malleability",
        title: "ECRecover Signature Malleability",
        severity: "high",
        description: "Signature replay vulnerabilities due to ECDSA signature malleability in cross-domain transactions.",
        attackVector: ["Signature manipulation"],
        affectedContracts: ["L1CrossDomainMessenger", "L2CrossDomainMessenger"]
      },
      {
        id: "protocol-insolvency",
        title: "Protocol Insolvency Risk",
        severity: "critical",
        description: "Withdrawal mechanisms fail to validate the protocol has sufficient funds to cover withdrawals.",
        attackVector: ["Excessive withdrawals"],
        affectedContracts: ["L2ToL1MessagePasser"]
      },
      {
        id: "unenforceable-timeouts",
        title: "Unenforceable Challenge Timeouts",
        severity: "medium",
        description: "Challenge timeouts can be avoided due to a flaw in the timeout enforcement mechanism.",
        attackVector: ["Challenge timeout avoidance"],
        affectedContracts: ["FaultDisputeGame"]
      },
      {
        id: "invalid-target-handling",
        title: "Invalid Target Handling",
        severity: "medium",
        description: "Improper validation of message target addresses in cross-domain messaging.",
        attackVector: ["Invalid address targeting"],
        affectedContracts: ["L1CrossDomainMessenger", "L2CrossDomainMessenger"]
      },
      {
        id: "transaction-sequencing-attack",
        title: "Transaction Sequencing Attack",
        severity: "high",
        description: "Transaction ordering can be manipulated to gain privileged information or extract value.",
        attackVector: ["MEV-style attack"],
        affectedContracts: ["SequencerInbox"]
      },
      {
        id: "excessive-gas-usage",
        title: "Excessive Gas Usage Attack",
        severity: "medium",
        description: "Cross-domain messages can be crafted to consume excessive gas, potentially causing denial of service.",
        attackVector: ["Gas exhaustion"],
        affectedContracts: ["L1CrossDomainMessenger", "L2CrossDomainMessenger"]
      }
    ].forEach(vuln => {
      this.vulnerabilities.set(vuln.id, vuln as Vulnerability);
    });
  }
}

export const storage = new MemStorage();
