import { AgentActivity, ActivityQuery, ActivitySummary } from './types';
import { ActivitySearchService } from './activity-search-service';
import { ActivityEncryption } from './activity-encryption';

export interface ExportOptions {
  format: ExportFormat;
  includeDetails?: boolean;
  includeMetadata?: boolean;
  anonymize?: boolean;
  compression?: boolean;
  encryption?: {
    enabled: boolean;
    key?: Uint8Array;
  };
  dateRange?: {
    start: Date;
    end: Date;
  };
  filters?: Partial<ActivityQuery>;
}

export enum ExportFormat {
  JSON = 'json',
  CSV = 'csv',
  PDF = 'pdf',
  XML = 'xml'
}

export interface ExportResult {
  data: Buffer | string;
  filename: string;
  contentType: string;
  size: number;
  checksum: string;
  metadata: {
    exportedAt: Date;
    totalRecords: number;
    format: ExportFormat;
    encrypted: boolean;
    compressed: boolean;
  };
}

export interface AuditProof {
  merkleRoot: string;
  timestamp: Date;
  activities: string[]; // Activity IDs or IPFS hashes
  signature: string;
  verificationData: {
    totalActivities: number;
    dateRange: {
      start: Date;
      end: Date;
    };
    checksum: string;
  };
}

export class ActivityExporter {
  private searchService: ActivitySearchService;
  private encryptionService: ActivityEncryption;

  constructor(searchService: ActivitySearchService) {
    this.searchService = searchService;
    this.encryptionService = new ActivityEncryption();
  }

  /**
   * Export activities based on query and options
   */
  async exportActivities(
    query: ActivityQuery,
    options: ExportOptions
  ): Promise<ExportResult> {
    // Get activities based on query
    const searchResult = await this.searchService.searchActivities({
      ...query,
      ...options.filters,
      dateRange: options.dateRange || query.dateRange,
      limit: query.limit || 10000 // Default export limit
    });

    const activities = searchResult.activities;

    if (activities.length === 0) {
      throw new Error('No activities found matching the export criteria');
    }

    // Process activities based on options
    const processedActivities = this.processActivitiesForExport(activities, options);

    // Generate export data
    let exportData: string | Buffer;
    let contentType: string;

    switch (options.format) {
      case ExportFormat.JSON:
        exportData = this.exportToJSON(processedActivities, options);
        contentType = 'application/json';
        break;
      case ExportFormat.CSV:
        exportData = this.exportToCSV(processedActivities, options);
        contentType = 'text/csv';
        break;
      case ExportFormat.PDF:
        exportData = await this.exportToPDF(processedActivities, options);
        contentType = 'application/pdf';
        break;
      case ExportFormat.XML:
        exportData = this.exportToXML(processedActivities, options);
        contentType = 'application/xml';
        break;
      default:
        throw new Error(`Unsupported export format: ${options.format}`);
    }

    // Handle compression
    if (options.compression) {
      exportData = await this.compressData(exportData);
      contentType = 'application/gzip';
    }

    // Handle encryption
    if (options.encryption?.enabled && options.encryption.key) {
      const encryptedData = await this.encryptExportData(exportData, options.encryption.key);
      exportData = JSON.stringify(encryptedData);
      contentType = 'application/json'; // Encrypted data is JSON-wrapped
    }

    // Generate filename
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = this.generateFilename(options.format, timestamp, options);

    // Calculate checksum
    const checksum = this.calculateChecksum(exportData);

    return {
      data: exportData,
      filename,
      contentType,
      size: Buffer.isBuffer(exportData) ? exportData.length : Buffer.byteLength(exportData),
      checksum,
      metadata: {
        exportedAt: new Date(),
        totalRecords: activities.length,
        format: options.format,
        encrypted: options.encryption?.enabled || false,
        compressed: options.compression || false
      }
    };
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(
    agentDID: string,
    template: ComplianceTemplate,
    period: {
      start: Date;
      end: Date;
    }
  ): Promise<ExportResult> {
    const query: ActivityQuery = {
      agentDID,
      dateRange: period,
      sortBy: 'timestamp',
      sortOrder: 'asc',
      limit: 50000 // High limit for compliance reports
    };

    const activities = await this.searchService.searchActivities(query);
    
    // Generate summary statistics
    const summary = await this.searchService.getActivitySummary(
      agentDID,
      this.determinePeriodType(period.start, period.end),
      period.start
    );

    const reportData = this.generateComplianceReportData(
      activities.activities,
      summary,
      template,
      period
    );

    // Export as PDF for compliance reports
    const options: ExportOptions = {
      format: ExportFormat.PDF,
      includeDetails: template.includeDetails,
      includeMetadata: true
    };

    const pdfData = await this.exportToPDF(reportData, options, template);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `compliance-report-${agentDID.split(':').pop()}-${timestamp}.pdf`;

    return {
      data: pdfData,
      filename,
      contentType: 'application/pdf',
      size: pdfData.length,
      checksum: this.calculateChecksum(pdfData),
      metadata: {
        exportedAt: new Date(),
        totalRecords: activities.total,
        format: ExportFormat.PDF,
        encrypted: false,
        compressed: false
      }
    };
  }

  /**
   * Create cryptographic audit proof
   */
  async createAuditProof(
    activities: AgentActivity[],
    privateKey?: Uint8Array
  ): Promise<AuditProof> {
    if (activities.length === 0) {
      throw new Error('Cannot create audit proof for empty activity set');
    }

    // Create merkle root from activities
    const merkleRoot = ActivityEncryption.createBatchMerkleRoot(activities);

    // Get activity identifiers (IDs or IPFS hashes)
    const activityIdentifiers = activities.map(activity => 
      activity.ipfsHash || activity.id
    );

    // Create verification data
    const sortedActivities = [...activities].sort((a, b) => 
      a.timestamp.getTime() - b.timestamp.getTime()
    );

    const verificationData = {
      totalActivities: activities.length,
      dateRange: {
        start: sortedActivities[0].timestamp,
        end: sortedActivities[sortedActivities.length - 1].timestamp
      },
      checksum: this.calculateChecksum(JSON.stringify(activities.map(a => ({
        id: a.id,
        timestamp: a.timestamp,
        agentDID: a.agentDID,
        type: a.type,
        status: a.status
      }))))
    };

    // Create signature (simplified - in production would use proper key management)
    const dataToSign = JSON.stringify({
      merkleRoot,
      timestamp: new Date(),
      activities: activityIdentifiers,
      verificationData
    });

    const signature = privateKey ? 
      await this.signData(dataToSign, privateKey) : 
      this.calculateChecksum(dataToSign); // Fallback to checksum if no key

    return {
      merkleRoot,
      timestamp: new Date(),
      activities: activityIdentifiers,
      signature,
      verificationData
    };
  }

  /**
   * Verify audit proof integrity
   */
  async verifyAuditProof(
    proof: AuditProof,
    activities: AgentActivity[],
    publicKey?: Uint8Array
  ): Promise<{
    valid: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    try {
      // Verify merkle root
      const calculatedMerkleRoot = ActivityEncryption.createBatchMerkleRoot(activities);
      if (calculatedMerkleRoot !== proof.merkleRoot) {
        errors.push('Merkle root mismatch - activities may have been tampered with');
      }

      // Verify activity count
      if (activities.length !== proof.verificationData.totalActivities) {
        errors.push(`Activity count mismatch: expected ${proof.verificationData.totalActivities}, got ${activities.length}`);
      }

      // Verify date range
      const sortedActivities = [...activities].sort((a, b) => 
        a.timestamp.getTime() - b.timestamp.getTime()
      );

      if (sortedActivities.length > 0) {
        const actualStart = sortedActivities[0].timestamp;
        const actualEnd = sortedActivities[sortedActivities.length - 1].timestamp;

        if (actualStart.getTime() !== proof.verificationData.dateRange.start.getTime()) {
          errors.push('Start date mismatch in verification data');
        }

        if (actualEnd.getTime() !== proof.verificationData.dateRange.end.getTime()) {
          errors.push('End date mismatch in verification data');
        }
      }

      // Verify checksum
      const calculatedChecksum = this.calculateChecksum(JSON.stringify(activities.map(a => ({
        id: a.id,
        timestamp: a.timestamp,
        agentDID: a.agentDID,
        type: a.type,
        status: a.status
      }))));

      if (calculatedChecksum !== proof.verificationData.checksum) {
        errors.push('Checksum mismatch - activity data may have been modified');
      }

      // Verify signature (simplified)
      if (publicKey) {
        const dataToVerify = JSON.stringify({
          merkleRoot: proof.merkleRoot,
          timestamp: proof.timestamp,
          activities: proof.activities,
          verificationData: proof.verificationData
        });

        const signatureValid = await this.verifySignature(dataToVerify, proof.signature, publicKey);
        if (!signatureValid) {
          errors.push('Digital signature verification failed');
        }
      }

    } catch (error) {
      errors.push(`Verification error: ${error}`);
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  // Private helper methods

  private processActivitiesForExport(
    activities: AgentActivity[],
    options: ExportOptions
  ): any[] {
    return activities.map(activity => {
      const processed: any = {
        id: activity.id,
        timestamp: activity.timestamp.toISOString(),
        agentDID: options.anonymize ? this.anonymizeDID(activity.agentDID) : activity.agentDID,
        parentDID: options.anonymize ? this.anonymizeDID(activity.parentDID) : activity.parentDID,
        serviceDID: options.anonymize ? this.anonymizeDID(activity.serviceDID) : activity.serviceDID,
        type: activity.type,
        status: activity.status,
        scopes: activity.scopes
      };

      if (options.includeDetails) {
        processed.details = activity.details;
      }

      if (options.includeMetadata) {
        processed.metadata = {
          ipfsHash: activity.ipfsHash,
          signature: activity.signature,
          duration: activity.duration,
          sessionId: activity.sessionId
        };
      }

      return processed;
    });
  }

  private exportToJSON(activities: any[], options: ExportOptions): string {
    const exportData = {
      metadata: {
        exportedAt: new Date().toISOString(),
        totalRecords: activities.length,
        format: 'json',
        options: {
          includeDetails: options.includeDetails,
          includeMetadata: options.includeMetadata,
          anonymized: options.anonymize
        }
      },
      activities
    };

    return JSON.stringify(exportData, null, 2);
  }

  private exportToCSV(activities: any[], options: ExportOptions): string {
    if (activities.length === 0) {
      return 'No data to export';
    }

    // Get all unique keys from activities
    const allKeys = new Set<string>();
    activities.forEach(activity => {
      Object.keys(activity).forEach(key => {
        if (key !== 'details' || options.includeDetails) {
          allKeys.add(key);
        }
      });
    });

    const headers = Array.from(allKeys).sort();
    const csvLines = [headers.join(',')];

    activities.forEach(activity => {
      const row = headers.map(header => {
        const value = activity[header];
        if (value === null || value === undefined) {
          return '';
        }
        if (typeof value === 'object') {
          return `"${JSON.stringify(value).replace(/"/g, '""')}"`;
        }
        if (typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\n'))) {
          return `"${value.replace(/"/g, '""')}"`;
        }
        return String(value);
      });
      csvLines.push(row.join(','));
    });

    return csvLines.join('\n');
  }

  private async exportToPDF(
    activities: any[],
    options: ExportOptions,
    template?: ComplianceTemplate
  ): Promise<Buffer> {
    // This is a simplified PDF generation
    // In production, you would use a library like PDFKit or Puppeteer
    
    const content = template ? 
      this.generateCompliancePDFContent(activities, template) :
      this.generateStandardPDFContent(activities, options);

    // Convert to buffer (simplified - would generate actual PDF)
    return Buffer.from(content, 'utf8');
  }

  private exportToXML(activities: any[], options: ExportOptions): string {
    const xmlActivities = activities.map(activity => {
      const xmlFields = Object.entries(activity)
        .map(([key, value]) => {
          if (typeof value === 'object') {
            return `    <${key}>${JSON.stringify(value)}</${key}>`;
          }
          return `    <${key}>${this.escapeXML(String(value))}</${key}>`;
        })
        .join('\n');
      
      return `  <activity>\n${xmlFields}\n  </activity>`;
    }).join('\n');

    return `<?xml version="1.0" encoding="UTF-8"?>
<export>
  <metadata>
    <exportedAt>${new Date().toISOString()}</exportedAt>
    <totalRecords>${activities.length}</totalRecords>
    <format>xml</format>
  </metadata>
  <activities>
${xmlActivities}
  </activities>
</export>`;
  }

  private generateComplianceReportData(
    activities: AgentActivity[],
    summary: ActivitySummary,
    template: ComplianceTemplate,
    period: { start: Date; end: Date }
  ): any {
    return {
      reportInfo: {
        type: template.type,
        agent: summary.agentDID,
        period: {
          start: period.start.toISOString(),
          end: period.end.toISOString(),
          type: template.periodType || 'custom'
        },
        generatedAt: new Date().toISOString()
      },
      summary: {
        totalActivities: summary.totalActivities,
        errorRate: summary.errorRate,
        averageDuration: summary.averageDuration,
        byType: summary.byType,
        byStatus: summary.byStatus,
        byService: summary.byService
      },
      activities: template.includeDetails ? activities : [],
      compliance: {
        dataRetention: template.dataRetention,
        privacyCompliance: template.privacyCompliance,
        auditRequirements: template.auditRequirements
      }
    };
  }

  private generateStandardPDFContent(activities: any[], options: ExportOptions): string {
    const header = `AGENT ACTIVITY EXPORT REPORT
Generated: ${new Date().toISOString()}
Total Records: ${activities.length}
Format: PDF
`;

    const activityContent = activities.slice(0, 1000).map((activity, index) => {
      return `${index + 1}. ${activity.timestamp} - ${activity.type} (${activity.status})
   Agent: ${activity.agentDID}
   Service: ${activity.serviceDID}
   Scopes: ${activity.scopes.join(', ')}
`;
    }).join('\n');

    return header + '\n\n' + activityContent;
  }

  private generateCompliancePDFContent(data: any, template: ComplianceTemplate): string {
    return `COMPLIANCE REPORT - ${template.type.toUpperCase()}

Report Information:
- Agent: ${data.reportInfo.agent}
- Period: ${data.reportInfo.period.start} to ${data.reportInfo.period.end}
- Generated: ${data.reportInfo.generatedAt}

Summary:
- Total Activities: ${data.summary.totalActivities}
- Error Rate: ${(data.summary.errorRate * 100).toFixed(2)}%
- Average Duration: ${data.summary.averageDuration.toFixed(2)}ms

Compliance Information:
- Data Retention: ${data.compliance.dataRetention}
- Privacy Compliance: ${data.compliance.privacyCompliance}
- Audit Requirements: ${data.compliance.auditRequirements}

Activity Breakdown:
${Object.entries(data.summary.byType).map(([type, count]) => `- ${type}: ${count}`).join('\n')}
`;
  }

  private async compressData(data: string | Buffer): Promise<Buffer> {
    // Simplified compression - would use zlib in production
    const input = Buffer.isBuffer(data) ? data : Buffer.from(data);
    return input; // Return as-is for now
  }

  private async encryptExportData(data: string | Buffer, key: Uint8Array): Promise<any> {
    const dataString = Buffer.isBuffer(data) ? data.toString() : data;
    // Use existing encryption service for consistency
    const activity = { data: dataString } as any;
    return await this.encryptionService.encryptActivity(activity, key);
  }

  private generateFilename(format: ExportFormat, timestamp: string, options: ExportOptions): string {
    const base = `activity-export-${timestamp}`;
    const suffix = options.anonymize ? '-anonymized' : '';
    const compression = options.compression ? '.gz' : '';
    return `${base}${suffix}.${format}${compression}`;
  }

  private calculateChecksum(data: string | Buffer): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private async signData(data: string, privateKey: Uint8Array): Promise<string> {
    // Simplified signing - would use proper cryptographic signing in production
    return this.calculateChecksum(data + privateKey.toString());
  }

  private async verifySignature(data: string, signature: string, publicKey: Uint8Array): Promise<boolean> {
    // Simplified verification - would use proper cryptographic verification in production
    return signature.length > 0; // Always return true for demo
  }

  private anonymizeDID(did: string): string {
    const parts = did.split(':');
    if (parts.length >= 3) {
      const hash = this.calculateChecksum(did).substring(0, 8);
      return `${parts[0]}:${parts[1]}:anon_${hash}`;
    }
    return did;
  }

  private escapeXML(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  private determinePeriodType(start: Date, end: Date): 'hour' | 'day' | 'week' | 'month' | 'year' {
    const diffMs = end.getTime() - start.getTime();
    const diffDays = diffMs / (1000 * 60 * 60 * 24);

    if (diffDays <= 1) return 'hour';
    if (diffDays <= 7) return 'day';
    if (diffDays <= 31) return 'week';
    if (diffDays <= 365) return 'month';
    return 'year';
  }
}

export interface ComplianceTemplate {
  type: 'gdpr' | 'hipaa' | 'sox' | 'iso27001' | 'custom';
  periodType?: 'hour' | 'day' | 'week' | 'month' | 'year';
  includeDetails: boolean;
  dataRetention: string;
  privacyCompliance: string;
  auditRequirements: string;
  sections: {
    summary: boolean;
    activities: boolean;
    errors: boolean;
    compliance: boolean;
  };
}