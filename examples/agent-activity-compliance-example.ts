/**
 * Agent Activity Export and Compliance Example
 * 
 * Demonstrates export capabilities, compliance reporting, archival policies, and GDPR compliance
 */

import { 
  ActivityMonitoringService,
  ActivityType,
  ActivityStatus,
  createActivity,
  ExportFormat,
  ActivityEncryption
} from '../src/agent/activity';
import { writeFileSync } from 'fs';

// Example 1: Basic Export Functionality
async function basicExportExample() {
  console.log('\n=== Basic Export Functionality ===\n');

  const monitoring = new ActivityMonitoringService({
    enableIndexing: true,
    enableStreaming: false,
    enableBatching: false
  });

  const agentDID = 'did:key:z6MkExportAgent123';
  const parentDID = 'did:key:z6MkExportParent456';
  const serviceDID = 'did:key:z6MkExportService789';

  // Generate sample activities
  console.log('Generating sample activities for export...');
  const activities = [];
  
  for (let i = 0; i < 20; i++) {
    const activity = await monitoring.logActivity(createActivity(
      i % 4 === 0 ? ActivityType.AUTHENTICATION :
      i % 4 === 1 ? ActivityType.DATA_ACCESS :
      i % 4 === 2 ? ActivityType.DATA_MODIFICATION :
      ActivityType.SCOPE_USAGE,
      {
        agentDID,
        parentDID,
        serviceDID,
        status: i % 7 === 0 ? ActivityStatus.FAILED : ActivityStatus.SUCCESS,
        scopes: i % 2 === 0 ? ['read:data'] : ['read:data', 'write:data'],
        details: {
          operation: `operation-${i + 1}`,
          resourceId: `resource-${Math.floor(i / 3) + 1}`,
          timestamp: new Date().toISOString(),
          metadata: {
            userAgent: 'Agent/1.0',
            ip: `192.168.1.${100 + (i % 20)}`
          }
        }
      }
    ));
    activities.push(activity);
  }

  console.log(`Generated ${activities.length} activities\n`);

  // Export to different formats
  const exportQuery = { agentDID };

  // 1. JSON Export
  console.log('1. Exporting to JSON...');
  const jsonExport = await monitoring.exportActivities(exportQuery, {
    format: ExportFormat.JSON,
    includeDetails: true,
    includeMetadata: true
  });

  console.log(`   - Size: ${jsonExport.size} bytes`);
  console.log(`   - Checksum: ${jsonExport.checksum.substring(0, 16)}...`);
  console.log(`   - Records: ${jsonExport.metadata.totalRecords}`);

  // 2. CSV Export
  console.log('\n2. Exporting to CSV...');
  const csvExport = await monitoring.exportActivities(exportQuery, {
    format: ExportFormat.CSV,
    includeDetails: false,
    includeMetadata: true
  });

  console.log(`   - Size: ${csvExport.size} bytes`);
  console.log(`   - Records: ${csvExport.metadata.totalRecords}`);

  // 3. Anonymized Export
  console.log('\n3. Exporting anonymized data...');
  const anonymizedExport = await monitoring.exportActivities(exportQuery, {
    format: ExportFormat.JSON,
    includeDetails: false,
    anonymize: true
  });

  console.log(`   - Size: ${anonymizedExport.size} bytes`);
  console.log(`   - Anonymized: DIDs are hashed`);

  // 4. Encrypted Export
  console.log('\n4. Exporting with encryption...');
  const encryptionKey = ActivityEncryption.generateKey();
  const encryptedExport = await monitoring.exportActivities(exportQuery, {
    format: ExportFormat.JSON,
    includeDetails: true,
    encryption: {
      enabled: true,
      key: encryptionKey
    }
  });

  console.log(`   - Size: ${encryptedExport.size} bytes`);
  console.log(`   - Encrypted: ${encryptedExport.metadata.encrypted}`);

  // 5. Compressed Export
  console.log('\n5. Exporting with compression...');
  const compressedExport = await monitoring.exportActivities(exportQuery, {
    format: ExportFormat.JSON,
    includeDetails: true,
    compression: true
  });

  console.log(`   - Size: ${compressedExport.size} bytes`);
  console.log(`   - Compressed: ${compressedExport.metadata.compressed}`);

  await monitoring.stop();
}

// Example 2: Compliance Reporting
async function complianceReportingExample() {
  console.log('\n=== Compliance Reporting ===\n');

  const monitoring = new ActivityMonitoringService({
    enableIndexing: true,
    enableStreaming: false
  });

  const agentDID = 'did:key:z6MkComplianceAgent123';
  const parentDID = 'did:key:z6MkComplianceParent456';
  const serviceDID = 'did:key:z6MkComplianceService789';

  // Register GDPR compliance information
  monitoring.registerGDPRCompliance(parentDID, {
    dataSubject: parentDID,
    processingBasis: 'consent',
    categories: ['identity_data', 'activity_logs', 'technical_data'],
    recipients: ['service_provider', 'compliance_auditor'],
    retentionPeriod: '90 days',
    rightsInformed: true,
    consentWithdrawable: true
  });

  // Generate diverse activities over time
  console.log('Generating compliance test data...');
  const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days ago
  
  for (let day = 0; day < 30; day++) {
    const dayActivities = Math.floor(Math.random() * 10) + 5; // 5-15 activities per day
    
    for (let i = 0; i < dayActivities; i++) {
      const timestamp = new Date(startDate.getTime() + day * 24 * 60 * 60 * 1000 + i * 60000);
      
      const activity = createActivity(
        Object.values(ActivityType)[Math.floor(Math.random() * Object.values(ActivityType).length)] as ActivityType,
        {
          agentDID,
          parentDID,
          serviceDID,
          status: Math.random() < 0.1 ? ActivityStatus.FAILED : ActivityStatus.SUCCESS,
          scopes: ['read:data', 'write:data'],
          details: {
            day: day + 1,
            dailyIndex: i + 1,
            complianceTest: true
          }
        }
      );

      // Set historical timestamp
      activity.timestamp = timestamp;
      await monitoring.logActivity(activity);
    }
  }

  console.log('Generated 30 days of compliance test data\n');

  // Generate GDPR Compliance Report
  console.log('1. Generating GDPR Compliance Report...');
  const gdprReport = await monitoring.generateComplianceReport(
    agentDID,
    {
      type: 'gdpr',
      includeDetails: true,
      dataRetention: '90 days as per GDPR Article 5',
      privacyCompliance: 'Compliant with GDPR Articles 6, 7, and 13',
      auditRequirements: 'Maintains audit trail per GDPR Article 30',
      sections: {
        summary: true,
        activities: true,
        errors: true,
        compliance: true
      }
    },
    {
      start: startDate,
      end: new Date()
    }
  );

  console.log(`   - Report size: ${gdprReport.size} bytes`);
  console.log(`   - Total activities: ${gdprReport.metadata.totalRecords}`);

  // Generate HIPAA Compliance Report
  console.log('\n2. Generating HIPAA Compliance Report...');
  const hipaaReport = await monitoring.generateComplianceReport(
    agentDID,
    {
      type: 'hipaa',
      includeDetails: false,
      dataRetention: '6 years as per HIPAA requirements',
      privacyCompliance: 'Compliant with HIPAA Security and Privacy Rules',
      auditRequirements: 'Maintains detailed audit logs per HIPAA § 164.312(b)',
      sections: {
        summary: true,
        activities: false,
        errors: true,
        compliance: true
      }
    },
    {
      start: startDate,
      end: new Date()
    }
  );

  console.log(`   - Report size: ${hipaaReport.size} bytes`);
  console.log(`   - Format: ${hipaaReport.metadata.format}`);

  // Create audit proof
  console.log('\n3. Creating cryptographic audit proof...');
  const auditProof = await monitoring.createAuditProof({ agentDID });
  
  console.log(`   - Merkle root: ${auditProof.merkleRoot.substring(0, 16)}...`);
  console.log(`   - Activities included: ${auditProof.activities.length}`);
  console.log(`   - Verification checksum: ${auditProof.verificationData.checksum.substring(0, 16)}...`);

  await monitoring.stop();
}

// Example 3: Archival Policies and Data Retention
async function archivalPoliciesExample() {
  console.log('\n=== Archival Policies and Data Retention ===\n');

  const monitoring = new ActivityMonitoringService({
    enableIndexing: true,
    enableStreaming: false,
    enableIPFS: false // Disable IPFS for this example
  });

  const agentDID = 'did:key:z6MkArchivalAgent123';
  const parentDID = 'did:key:z6MkArchivalParent456';
  const serviceDID = 'did:key:z6MkArchivalService789';

  // Add custom archival policies
  console.log('1. Setting up archival policies...');
  
  monitoring.addArchivalPolicy({
    id: 'test-policy',
    name: 'Test Data Retention',
    description: 'Short retention for test data',
    retentionPeriod: 7, // 7 days
    archiveAfter: 3, // Archive after 3 days
    autoDelete: false,
    compressionEnabled: true,
    encryptionRequired: false,
    triggers: [
      {
        type: 'time',
        condition: { days: 3 },
        action: 'archive'
      }
    ]
  });

  monitoring.addArchivalPolicy({
    id: 'sensitive-policy',
    name: 'Sensitive Data Retention',
    description: 'High security retention for sensitive data',
    retentionPeriod: 30, // 30 days
    archiveAfter: 14, // Archive after 14 days
    autoDelete: false,
    compressionEnabled: true,
    encryptionRequired: true,
    complianceStandard: 'gdpr',
    triggers: [
      {
        type: 'time',
        condition: { days: 14 },
        action: 'archive'
      }
    ]
  });

  // Add archival rules
  monitoring.addArchivalRule({
    agentDID,
    policy: { id: 'test-policy' } as any,
    priority: 10,
    active: true
  });

  console.log('Added archival policies and rules\n');

  // Generate old activities (simulated)
  console.log('2. Generating historical activities...');
  const oldDate = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000); // 10 days ago
  
  for (let i = 0; i < 15; i++) {
    const activity = createActivity(
      ActivityType.DATA_ACCESS,
      {
        agentDID,
        parentDID,
        serviceDID,
        status: ActivityStatus.SUCCESS,
        scopes: ['read:data'],
        details: {
          archivalExample: true,
          day: Math.floor(i / 3) + 1
        }
      }
    );
    
    // Set old timestamp
    activity.timestamp = new Date(oldDate.getTime() + i * 60000);
    await monitoring.logActivity(activity);
  }

  console.log('Generated 15 historical activities\n');

  // Archive old activities
  console.log('3. Archiving old activities...');
  const archiveResult = await monitoring.archiveActivities(
    {
      agentDID,
      dateRange: {
        start: new Date(0),
        end: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000) // Older than 5 days
      }
    },
    'test-policy',
    {
      deleteOriginals: false,
      createProof: true
    }
  );

  console.log(`   - Archived: ${archiveResult.metadata.totalActivities} activities`);
  console.log(`   - Archive ID: ${archiveResult.id}`);
  console.log(`   - Location: ${archiveResult.location}`);
  console.log(`   - Proof created: ${!!archiveResult.proof}`);

  // Generate retention report
  console.log('\n4. Generating data retention report...');
  const retentionReport = await monitoring.generateRetentionReport();
  
  console.log(`   - Total activities: ${retentionReport.totalActivities}`);
  console.log(`   - Archival records: ${retentionReport.archivalRecords}`);
  console.log(`   - Upcoming expirations: ${retentionReport.upcomingExpirations}`);
  console.log(`   - Compliance status: ${retentionReport.complianceStatus}`);

  await monitoring.stop();
}

// Example 4: GDPR Right to be Forgotten
async function gdprComplianceExample() {
  console.log('\n=== GDPR Right to be Forgotten ===\n');

  const monitoring = new ActivityMonitoringService({
    enableIndexing: true,
    enableStreaming: false
  });

  const userDID = 'did:key:z6MkGDPRUser123';
  const agent1DID = 'did:key:z6MkGDPRAgent1';
  const agent2DID = 'did:key:z6MkGDPRAgent2';
  const serviceDID = 'did:key:z6MkGDPRService';

  // Register GDPR compliance
  console.log('1. Registering GDPR compliance information...');
  monitoring.registerGDPRCompliance(userDID, {
    dataSubject: userDID,
    processingBasis: 'consent',
    categories: ['personal_data', 'activity_logs', 'authentication_data'],
    recipients: ['service_provider'],
    retentionPeriod: '90 days or until consent withdrawal',
    rightsInformed: true,
    consentWithdrawable: true
  });

  // Generate activities for multiple agents under this user
  console.log('2. Generating user activities across multiple agents...');
  
  const agents = [agent1DID, agent2DID];
  let totalActivities = 0;
  
  for (const agentDID of agents) {
    for (let i = 0; i < 25; i++) {
      await monitoring.logActivity(createActivity(
        Object.values(ActivityType)[i % Object.values(ActivityType).length] as ActivityType,
        {
          agentDID,
          parentDID: userDID,
          serviceDID,
          status: ActivityStatus.SUCCESS,
          scopes: ['read:profile', 'write:data'],
          details: {
            gdprExample: true,
            personalData: {
              userId: userDID.split(':').pop(),
              sessionId: `session-${Math.floor(i / 5)}`
            }
          }
        }
      ));
      totalActivities++;
    }
  }

  console.log(`Generated ${totalActivities} activities across ${agents.length} agents\n`);

  // Show current data status
  console.log('3. Current data status before GDPR deletion...');
  const beforeStats = await monitoring.getMonitoringStats();
  console.log(`   - Total activities: ${beforeStats.activities.total}`);

  // User exercises right to be forgotten
  console.log('4. Processing GDPR data deletion request...');
  const deletionResult = await monitoring.handleGDPRDataDeletion(userDID);
  
  console.log(`   - Activities deleted: ${deletionResult.activitiesDeleted}`);
  console.log(`   - Archives deleted: ${deletionResult.archivesDeleted}`);

  // Show data status after deletion
  console.log('\n5. Data status after GDPR deletion...');
  const afterStats = await monitoring.getMonitoringStats();
  console.log(`   - Total activities: ${afterStats.activities.total}`);
  console.log(`   - Deleted activities: ${beforeStats.activities.total - afterStats.activities.total}`);

  // Verify user data is gone
  console.log('\n6. Verifying complete data removal...');
  try {
    const userActivities = await monitoring.searchActivities({ parentDID: userDID });
    console.log(`   - Remaining user activities: ${userActivities.total}`);
    
    if (userActivities.total === 0) {
      console.log('   ✅ GDPR deletion successful - no user data remains');
    } else {
      console.log('   ❌ GDPR deletion incomplete - user data still exists');
    }
  } catch (error) {
    console.log('   ✅ GDPR deletion successful - user data completely removed');
  }

  await monitoring.stop();
}

// Example 5: Complete Compliance Workflow
async function completeComplianceWorkflow() {
  console.log('\n=== Complete Compliance Workflow ===\n');

  const monitoring = new ActivityMonitoringService({
    enableIndexing: true,
    enableStreaming: false,
    enableIPFS: false
  });

  // Step 1: Setup
  console.log('Step 1: Setting up compliance framework...');
  const companyDID = 'did:key:z6MkCompany123';
  const agentDID = 'did:key:z6MkWorkflowAgent';
  const serviceDID = 'did:key:z6MkWorkflowService';

  monitoring.registerGDPRCompliance(companyDID, {
    dataSubject: companyDID,
    processingBasis: 'legitimate_interests',
    categories: ['business_data', 'security_logs', 'audit_trails'],
    recipients: ['internal_audit', 'compliance_team'],
    retentionPeriod: '7 years for audit purposes',
    rightsInformed: true,
    consentWithdrawable: false
  });

  // Step 2: Generate business activities
  console.log('\nStep 2: Generating business activities...');
  const startDate = new Date(Date.now() - 180 * 24 * 60 * 60 * 1000); // 6 months ago
  
  for (let week = 0; week < 26; week++) {
    const weeklyActivities = Math.floor(Math.random() * 50) + 100; // 100-150 per week
    
    for (let i = 0; i < weeklyActivities; i++) {
      const activity = createActivity(
        Object.values(ActivityType)[Math.floor(Math.random() * Object.values(ActivityType).length)] as ActivityType,
        {
          agentDID,
          parentDID: companyDID,
          serviceDID,
          status: Math.random() < 0.05 ? ActivityStatus.FAILED : ActivityStatus.SUCCESS,
          scopes: ['read:business_data', 'write:reports'],
          details: {
            week: week + 1,
            businessUnit: ['sales', 'marketing', 'operations'][Math.floor(Math.random() * 3)],
            complianceWorkflow: true
          }
        }
      );
      
      activity.timestamp = new Date(startDate.getTime() + week * 7 * 24 * 60 * 60 * 1000 + i * 300000);
      await monitoring.logActivity(activity);
    }
  }

  console.log('Generated 6 months of business activities');

  // Step 3: Export for quarterly audit
  console.log('\nStep 3: Exporting quarterly audit data...');
  const quarterEnd = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  const quarterStart = new Date(quarterEnd.getTime() - 90 * 24 * 60 * 60 * 1000);
  
  const quarterlyExport = await monitoring.exportActivities(
    {
      agentDID,
      dateRange: { start: quarterStart, end: quarterEnd }
    },
    {
      format: ExportFormat.CSV,
      includeDetails: true,
      includeMetadata: true,
      compression: true
    }
  );

  console.log(`   - Quarterly export: ${quarterlyExport.size} bytes`);
  console.log(`   - Activities: ${quarterlyExport.metadata.totalRecords}`);

  // Step 4: Generate compliance reports
  console.log('\nStep 4: Generating compliance reports...');
  
  const complianceReports = await Promise.all([
    monitoring.generateComplianceReport(agentDID, {
      type: 'sox',
      includeDetails: true,
      dataRetention: '7 years per SOX requirements',
      privacyCompliance: 'Internal business data only',
      auditRequirements: 'Section 404 compliance maintained',
      sections: { summary: true, activities: true, errors: true, compliance: true }
    }, { start: quarterStart, end: quarterEnd }),
    
    monitoring.generateComplianceReport(agentDID, {
      type: 'iso27001',
      includeDetails: false,
      dataRetention: '3 years for security incidents',
      privacyCompliance: 'ISO 27001 Annex A.18 compliance',
      auditRequirements: 'Security monitoring per ISO 27001',
      sections: { summary: true, activities: false, errors: true, compliance: true }
    }, { start: quarterStart, end: quarterEnd })
  ]);

  console.log(`   - SOX report: ${complianceReports[0].size} bytes`);
  console.log(`   - ISO 27001 report: ${complianceReports[1].size} bytes`);

  // Step 5: Create audit proof
  console.log('\nStep 5: Creating cryptographic audit proof...');
  const auditProof = await monitoring.createAuditProof({
    agentDID,
    dateRange: { start: quarterStart, end: quarterEnd }
  });

  console.log(`   - Proof created for ${auditProof.activities.length} activities`);
  console.log(`   - Merkle root: ${auditProof.merkleRoot}`);

  // Step 6: Archive old data
  console.log('\nStep 6: Archiving old data per retention policy...');
  const archiveDate = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000); // 4 months ago
  
  const archiveResult = await monitoring.archiveActivities(
    {
      agentDID,
      dateRange: { start: new Date(0), end: archiveDate }
    },
    'long-term',
    { deleteOriginals: true, createProof: true }
  );

  console.log(`   - Archived: ${archiveResult.metadata.totalActivities} activities`);
  console.log(`   - Retention policy: 7 years`);

  // Step 7: Final compliance summary
  console.log('\nStep 7: Final compliance status...');
  const finalStats = await monitoring.getMonitoringStats();
  const retentionReport = await monitoring.generateRetentionReport();

  console.log(`   - Active activities: ${finalStats.activities.total}`);
  console.log(`   - Archived records: ${retentionReport.archivalRecords}`);
  console.log(`   - Compliance status: ${retentionReport.complianceStatus}`);
  console.log('   ✅ Compliance workflow completed successfully');

  await monitoring.stop();
}

// Run examples
async function runExamples() {
  console.log('=== Agent Activity Export and Compliance Examples ===');

  try {
    await basicExportExample();
    await complianceReportingExample();
    await archivalPoliciesExample();
    await gdprComplianceExample();
    await completeComplianceWorkflow();
    
    console.log('\n=== All Compliance Examples Completed Successfully ===');
  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Execute
runExamples().catch(console.error);