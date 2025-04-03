import { pgTable, text, serial, integer, boolean, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const vulnerabilities = pgTable("vulnerabilities", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  severity: text("severity").notNull(),
  description: text("description").notNull(),
  attackVector: jsonb("attack_vector").notNull(),
  affectedContracts: jsonb("affected_contracts").notNull(),
  vulnerableContract: jsonb("vulnerable_contract").notNull(),
  exploitScript: jsonb("exploit_script").notNull(),
  maliciousContract: jsonb("malicious_contract"),
  explanation: text("explanation").notNull(),
  keyPoints: jsonb("key_points").notNull(),
  recommendations: jsonb("recommendations").notNull(),
  securityInsight: text("security_insight"),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilities);

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type Vulnerability = typeof vulnerabilities.$inferSelect;

// Memory storage extends to support vulnerability operations
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
  
  // Initialize with vulnerabilities from the hardcoded data
  private initializeVulnerabilities() {
    // Import vulnerability data from a local JSON or hardcoded values
    // This would normally come from an external source or database
    const vulnerabilityData = require('../client/src/lib/vulnerabilities').vulnerabilities;
    
    for (const vulnerability of vulnerabilityData) {
      this.vulnerabilities.set(vulnerability.id, vulnerability);
    }
  }
}

export const storage = new MemStorage();
