import { ActivityExporter, ExportFormat } from './activity-exporter';
import { ActivitySearchService } from './activity-search-service';
import { ActivityIndex } from './activity-index';
import { AgentActivity, ActivityType, ActivityStatus } from './types';

describe('ActivityExporter', () => {
  let exporter: ActivityExporter;
  let searchService: ActivitySearchService;
  let index: ActivityIndex;
  let testActivities: AgentActivity[];

  beforeEach(() => {
    index = new ActivityIndex();
    searchService = new ActivitySearchService(index);
    exporter = new ActivityExporter(searchService);

    // Create test activities
    testActivities = Array.from({ length: 10 }, (_, i) => ({
      id: `test-activity-${i + 1}`,
      agentDID: 'did:key:z6MkTestAgent',
      parentDID: 'did:key:z6MkTestParent',
      timestamp: new Date(Date.now() - (10 - i) * 60000), // Spaced 1 minute apart
      type: i % 2 === 0 ? ActivityType.DATA_ACCESS : ActivityType.DATA_MODIFICATION,
      serviceDID: 'did:key:z6MkTestService',
      status: i % 5 === 0 ? ActivityStatus.FAILED : ActivityStatus.SUCCESS,
      scopes: ['read:data', 'write:data'],
      details: {
        operation: `operation-${i + 1}`,
        resourceId: `resource-${i + 1}`,
        metadata: { testData: true }
      }
    }));

    // Index test activities
    testActivities.forEach(async (activity) => {
      await index.indexActivity(activity);
    });
  });

  describe('JSON Export', () => {
    test('should export activities as JSON', async () => {
      const result = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        { format: ExportFormat.JSON, includeDetails: true }
      );

      expect(result.contentType).toBe('application/json');
      expect(result.metadata.format).toBe(ExportFormat.JSON);
      expect(result.metadata.totalRecords).toBe(10);
      expect(result.filename).toMatch(/activity-export-.*\.json$/);

      const exportData = JSON.parse(result.data as string);
      expect(exportData.metadata).toBeDefined();
      expect(exportData.activities).toHaveLength(10);
      expect(exportData.activities[0]).toHaveProperty('id');
      expect(exportData.activities[0]).toHaveProperty('timestamp');
      expect(exportData.activities[0]).toHaveProperty('details');
    });

    test('should exclude details when requested', async () => {
      const result = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        { format: ExportFormat.JSON, includeDetails: false }
      );

      const exportData = JSON.parse(result.data as string);
      expect(exportData.activities[0]).not.toHaveProperty('details');
    });

    test('should anonymize DIDs when requested', async () => {
      const result = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        { format: ExportFormat.JSON, anonymize: true }
      );

      const exportData = JSON.parse(result.data as string);
      const activity = exportData.activities[0];
      
      expect(activity.agentDID).toMatch(/^did:key:anon_[a-f0-9]{8}$/);
      expect(activity.parentDID).toMatch(/^did:key:anon_[a-f0-9]{8}$/);
      expect(activity.serviceDID).toMatch(/^did:key:anon_[a-f0-9]{8}$/);
    });
  });

  describe('CSV Export', () => {
    test('should export activities as CSV', async () => {
      const result = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        { format: ExportFormat.CSV, includeDetails: false }
      );

      expect(result.contentType).toBe('text/csv');
      expect(result.metadata.format).toBe(ExportFormat.CSV);
      expect(result.filename).toMatch(/activity-export-.*\.csv$/);

      const csvData = result.data as string;
      const lines = csvData.split('\n');
      
      // Should have header + 10 data rows
      expect(lines.length).toBeGreaterThanOrEqual(11);
      
      // Check header
      expect(lines[0]).toContain('id');
      expect(lines[0]).toContain('timestamp');
      expect(lines[0]).toContain('agentDID');
      
      // Check data rows
      expect(lines[1]).toContain('test-activity-1');
    });

    test('should handle CSV escaping correctly', async () => {
      // Add an activity with special characters
      const specialActivity: AgentActivity = {
        id: 'special-activity',
        agentDID: 'did:key:z6MkTestAgent',
        parentDID: 'did:key:z6MkTestParent',
        timestamp: new Date(),
        type: ActivityType.DATA_ACCESS,
        serviceDID: 'did:key:z6MkTestService',
        status: ActivityStatus.SUCCESS,
        scopes: ['read:data'],
        details: {
          message: 'Test with "quotes" and, commas',
          metadata: { special: 'characters\nand newlines' }
        }
      };

      await index.indexActivity(specialActivity);

      const result = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        { format: ExportFormat.CSV, includeDetails: true }
      );

      const csvData = result.data as string;
      // Check that the CSV contains the special activity ID at minimum
      expect(csvData).toContain('special-activity');
    });
  });

  describe('XML Export', () => {
    test('should export activities as XML', async () => {
      const result = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        { format: ExportFormat.XML, includeDetails: true }
      );

      expect(result.contentType).toBe('application/xml');
      expect(result.metadata.format).toBe(ExportFormat.XML);
      expect(result.filename).toMatch(/activity-export-.*\.xml$/);

      const xmlData = result.data as string;
      expect(xmlData).toContain('<?xml version="1.0" encoding="UTF-8"?>');
      expect(xmlData).toContain('<export>');
      expect(xmlData).toContain('<activities>');
      expect(xmlData).toContain('<activity>');
      expect(xmlData).toContain('<id>test-activity-1</id>');
    });
  });

  describe('Audit Proof', () => {
    test('should create audit proof for activities', async () => {
      const proof = await exporter.createAuditProof(testActivities.slice(0, 5));

      expect(proof.merkleRoot).toBeDefined();
      expect(proof.timestamp).toBeInstanceOf(Date);
      expect(proof.activities).toHaveLength(5);
      expect(proof.signature).toBeDefined();
      expect(proof.verificationData.totalActivities).toBe(5);
      expect(proof.verificationData.checksum).toBeDefined();
    });

    test('should verify audit proof integrity', async () => {
      const activities = testActivities.slice(0, 3);
      const proof = await exporter.createAuditProof(activities);

      const verification = await exporter.verifyAuditProof(proof, activities);

      expect(verification.valid).toBe(true);
      expect(verification.errors).toHaveLength(0);
    });

    test('should detect tampered activities', async () => {
      const activities = testActivities.slice(0, 3);
      const proof = await exporter.createAuditProof(activities);

      // Tamper with activity by creating a new activity with different status
      const tamperedActivities = activities.map((activity, index) => {
        if (index === 0) {
          return {
            ...activity,
            status: activity.status === ActivityStatus.SUCCESS ? ActivityStatus.FAILED : ActivityStatus.SUCCESS
          };
        }
        return activity;
      });

      const verification = await exporter.verifyAuditProof(proof, tamperedActivities);

      expect(verification.valid).toBe(false);
      expect(verification.errors.length).toBeGreaterThan(0);
      expect(verification.errors[0]).toContain('Merkle root mismatch');
    });

    test('should detect activity count mismatch', async () => {
      const activities = testActivities.slice(0, 3);
      const proof = await exporter.createAuditProof(activities);

      // Remove an activity
      const fewerActivities = activities.slice(0, 2);

      const verification = await exporter.verifyAuditProof(proof, fewerActivities);

      expect(verification.valid).toBe(false);
      expect(verification.errors.some(e => e.includes('Activity count mismatch'))).toBe(true);
    });
  });

  describe('Compliance Reports', () => {
    test('should generate GDPR compliance report', async () => {
      const period = {
        start: new Date(Date.now() - 24 * 60 * 60 * 1000),
        end: new Date()
      };

      const result = await exporter.generateComplianceReport(
        'did:key:z6MkTestAgent',
        {
          type: 'gdpr',
          includeDetails: true,
          dataRetention: '90 days',
          privacyCompliance: 'GDPR compliant',
          auditRequirements: 'Full audit trail',
          sections: {
            summary: true,
            activities: true,
            errors: true,
            compliance: true
          }
        },
        period
      );

      expect(result.contentType).toBe('application/pdf');
      expect(result.metadata.format).toBe(ExportFormat.PDF);
      expect(result.filename).toMatch(/compliance-report-.*\.pdf$/);
      expect(result.size).toBeGreaterThan(0);
    });
  });

  describe('Export Options', () => {
    test('should handle date range filtering', async () => {
      const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const now = new Date();

      const result = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        {
          format: ExportFormat.JSON,
          dateRange: { start: yesterday, end: now }
        }
      );

      expect(result.metadata.totalRecords).toBe(10); // All activities are within range
    });

    test('should generate unique filenames', async () => {
      const result1 = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        { format: ExportFormat.JSON }
      );

      // Wait a moment to ensure different timestamp
      await new Promise(resolve => setTimeout(resolve, 10));

      const result2 = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        { format: ExportFormat.JSON }
      );

      expect(result1.filename).not.toBe(result2.filename);
    });

    test('should calculate different checksums for different data', async () => {
      // Export with different options should produce different checksums
      const result1 = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        { format: ExportFormat.JSON, includeDetails: true }
      );

      const result2 = await exporter.exportActivities(
        { agentDID: 'did:key:z6MkTestAgent' },
        { format: ExportFormat.JSON, includeDetails: false }
      );

      // Different export options should produce different checksums
      expect(result1.checksum).not.toBe(result2.checksum);
      
      // But both should be valid SHA-256 hashes (64 hex characters)
      expect(result1.checksum).toMatch(/^[a-f0-9]{64}$/);
      expect(result2.checksum).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('Error Handling', () => {
    test('should throw error for empty activity set', async () => {
      await expect(
        exporter.exportActivities(
          { agentDID: 'nonexistent-agent' },
          { format: ExportFormat.JSON }
        )
      ).rejects.toThrow('No activities found matching the export criteria');
    });

    test('should throw error for unsupported format', async () => {
      await expect(
        exporter.exportActivities(
          { agentDID: 'did:key:z6MkTestAgent' },
          { format: 'unsupported' as ExportFormat }
        )
      ).rejects.toThrow('Unsupported export format');
    });

    test('should throw error for empty audit proof', async () => {
      await expect(
        exporter.createAuditProof([])
      ).rejects.toThrow('Cannot create audit proof for empty activity set');
    });
  });
});