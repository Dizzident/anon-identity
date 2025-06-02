/**
 * Revocation Scenarios Example
 * 
 * This example demonstrates various revocation scenarios:
 * 1. Individual agent revocation
 * 2. Cascading revocation through delegation trees
 * 3. Service-specific revocation
 * 4. Emergency revocation procedures
 * 5. Audit trail and monitoring
 * 6. Revocation recovery and re-delegation
 */

import { AgentIdentityManager } from '../src/agent/agent-identity';
import { DelegationManager } from '../src/agent/delegation-manager';
import { DelegationChainValidator } from '../src/agent/delegation-chain-validator';
import { CascadingRevocationManager } from '../src/agent/revocation/cascading-revocation-manager';
import { EnhancedAuditTrail } from '../src/agent/revocation/audit-trail';
import { RevocationMonitoringDashboard } from '../src/agent/revocation/monitoring-dashboard';
import { ActivityLogger } from '../src/agent/activity/activity-logger';
import { CommunicationManager } from '../src/agent/communication/communication-manager';
import { DirectChannel } from '../src/agent/communication/channels/direct-channel';
import { generateKeyPair } from '../src/core/crypto';
import { DIDService } from '../src/core/did';

async function revocationScenariosExample() {
  console.log('🚫 Revocation Scenarios Example\n');

  // Initialize core components
  const agentManager = new AgentIdentityManager();
  const delegationManager = new DelegationManager();
  const chainValidator = new DelegationChainValidator(delegationManager, agentManager);
  const activityLogger = new ActivityLogger();
  
  // Setup communication for notifications
  const channel = new DirectChannel('revocation-notifications');
  const communicationManager = new CommunicationManager(
    null as any, // Will be set per agent
    agentManager,
    delegationManager,
    null as any, // Policy engine not needed for this example
    activityLogger
  );
  communicationManager.addChannel(channel);
  await communicationManager.connectAll();

  // Initialize revocation and monitoring systems
  const revocationManager = new CascadingRevocationManager(
    agentManager,
    chainValidator,
    communicationManager,
    activityLogger
  );

  const auditTrail = new EnhancedAuditTrail(activityLogger);
  const dashboard = new RevocationMonitoringDashboard(
    auditTrail,
    revocationManager,
    agentManager,
    activityLogger
  );

  try {
    // 1. Create organizational structure for testing
    console.log('1️⃣  Setting up organizational structure...\n');

    // Create company CEO
    const ceoKeyPair = await generateKeyPair();
    const ceoDID = DIDService.createDIDKey(ceoKeyPair.publicKey).id;
    console.log(`👑 CEO DID: ${ceoDID.substring(0, 30)}...`);

    // Create department structure
    const departments = ['security', 'engineering', 'finance'];
    const departmentHeads = new Map();
    const teamMembers = new Map();

    for (const dept of departments) {
      // Create department head
      const head = await agentManager.createAgent(ceoDID, {
        name: `${dept.charAt(0).toUpperCase() + dept.slice(1)} Head`,
        description: `Head of ${dept} department`,
        canDelegate: true,
        maxDelegationDepth: 4
      });

      const headCredential = await delegationManager.createDelegationCredential(
        ceoDID,
        ceoKeyPair,
        head.did,
        head.name,
        {
          serviceDID: `${dept}-service`,
          scopes: [`admin:${dept}`, `read:${dept}`, `write:${dept}`, `manage:${dept}`],
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
        }
      );

      agentManager.addDelegationCredential(head.did, headCredential);
      departmentHeads.set(dept, head);

      // Create team members under each head
      const members = [];
      for (let i = 1; i <= 3; i++) {
        const member = await agentManager.createSubAgent(head.did, {
          name: `${dept.charAt(0).toUpperCase() + dept.slice(1)} Member ${i}`,
          description: `Team member ${i} in ${dept} department`,
          parentAgentDID: head.did,
          requestedScopes: [`read:${dept}`, `write:${dept}`]
        });

        const memberCredential = await delegationManager.createDelegationCredential(
          head.did,
          head.keyPair,
          member.did,
          member.name,
          {
            serviceDID: `${dept}-service`,
            scopes: [`read:${dept}`, `write:${dept}`],
            expiresAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000)
          }
        );

        agentManager.addDelegationCredential(member.did, memberCredential);
        members.push(member);
      }
      teamMembers.set(dept, members);

      console.log(`🏢 ${dept} department: 1 head + ${members.length} members`);
    }

    // Create contractors with limited access
    const contractors = [];
    const securityHead = departmentHeads.get('security');
    
    for (let i = 1; i <= 2; i++) {
      const contractor = await agentManager.createSubAgent(securityHead.did, {
        name: `Security Contractor ${i}`,
        description: `External security contractor ${i}`,
        parentAgentDID: securityHead.did,
        requestedScopes: ['read:security']
      });

      const contractorCredential = await delegationManager.createDelegationCredential(
        securityHead.did,
        securityHead.keyPair,
        contractor.did,
        contractor.name,
        {
          serviceDID: 'security-service',
          scopes: ['read:security'],
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // Shorter term
        }
      );

      agentManager.addDelegationCredential(contractor.did, contractorCredential);
      contractors.push(contractor);
    }

    console.log(`👷 ${contractors.length} security contractors created\n`);

    // 2. Scenario 1: Individual Agent Revocation
    console.log('2️⃣  Scenario 1: Individual Agent Revocation\n');

    const targetMember = teamMembers.get('engineering')[0];
    console.log(`🎯 Revoking individual agent: ${targetMember.name}`);

    const result1 = await revocationManager.revokeAgent({
      targetAgentDID: targetMember.did,
      reason: 'Performance issues - individual revocation',
      revokedBy: ceoDID,
      timestamp: new Date(),
      cascading: false
    });

    console.log(`✅ Revocation result: ${result1.success ? 'SUCCESS' : 'FAILED'}`);
    console.log(`   Revoked agents: ${result1.revokedAgents.length}`);
    console.log(`   Notifications sent: ${result1.notificationsSent}`);
    console.log(`   Agent still exists: ${agentManager.getAgent(targetMember.did) !== null}`);
    console.log(`   Agent is revoked: ${revocationManager.isAgentRevoked(targetMember.did)}`);

    // 3. Scenario 2: Cascading Revocation
    console.log('\n3️⃣  Scenario 2: Cascading Revocation\n');

    const financeHead = departmentHeads.get('finance');
    console.log(`🎯 Cascading revocation from: ${financeHead.name}`);
    console.log(`   Expected to revoke: head + 3 team members`);

    const result2 = await revocationManager.revokeAgent({
      targetAgentDID: financeHead.did,
      reason: 'Department restructuring - cascading revocation',
      revokedBy: ceoDID,
      timestamp: new Date(),
      cascading: true
    });

    console.log(`✅ Cascading revocation result: ${result2.success ? 'SUCCESS' : 'FAILED'}`);
    console.log(`   Revoked agents: ${result2.revokedAgents.length}`);
    console.log(`   Failed revocations: ${result2.failedRevocations.length}`);
    console.log(`   Notifications sent: ${result2.notificationsSent}`);

    // Verify all finance team members are revoked
    const financeMembers = teamMembers.get('finance');
    console.log('   Finance team revocation status:');
    console.log(`   📋 ${financeHead.name}: ${revocationManager.isAgentRevoked(financeHead.did) ? '❌ REVOKED' : '✅ ACTIVE'}`);
    for (const member of financeMembers) {
      console.log(`   📋 ${member.name}: ${revocationManager.isAgentRevoked(member.did) ? '❌ REVOKED' : '✅ ACTIVE'}`);
    }

    // 4. Scenario 3: Service-Specific Revocation
    console.log('\n4️⃣  Scenario 3: Service-Specific Revocation\n');

    const engineeringHead = departmentHeads.get('engineering');
    console.log(`🎯 Service-specific revocation for: ${engineeringHead.name}`);
    console.log(`   Revoking access to engineering-service only`);

    const result3 = await revocationManager.revokeAgent({
      targetAgentDID: engineeringHead.did,
      reason: 'Temporary security audit - service-specific',
      revokedBy: ceoDID,
      timestamp: new Date(),
      cascading: false,
      serviceDID: 'engineering-service'
    });

    console.log(`✅ Service-specific revocation: ${result3.success ? 'SUCCESS' : 'FAILED'}`);
    console.log(`   Agent globally revoked: ${revocationManager.isAgentRevoked(engineeringHead.did)}`);
    console.log(`   Engineering service revoked: ${revocationManager.isAgentRevoked(engineeringHead.did, 'engineering-service')}`);
    console.log(`   Other services revoked: ${revocationManager.isAgentRevoked(engineeringHead.did, 'other-service')}`);

    // 5. Scenario 4: Emergency Revocation
    console.log('\n5️⃣  Scenario 4: Emergency Revocation Procedure\n');

    console.log(`🚨 EMERGENCY: Security breach detected!`);
    console.log(`   Revoking all security contractors immediately`);

    const emergencyResults = [];
    for (const contractor of contractors) {
      const emergencyResult = await revocationManager.revokeAgent({
        targetAgentDID: contractor.did,
        reason: 'EMERGENCY: Security breach - immediate revocation',
        revokedBy: ceoDID,
        timestamp: new Date(),
        cascading: false
      });
      emergencyResults.push({ contractor: contractor.name, result: emergencyResult });
    }

    console.log('🚨 Emergency revocation results:');
    for (const { contractor, result } of emergencyResults) {
      console.log(`   ${contractor}: ${result.success ? '✅ REVOKED' : '❌ FAILED'}`);
    }

    // 6. Audit Trail Analysis
    console.log('\n6️⃣  Audit Trail Analysis\n');

    const auditEntries = revocationManager.getRevocationAudit();
    console.log(`📊 Total revocation entries: ${auditEntries.length}`);

    // Group by reason
    const reasonCounts = new Map();
    auditEntries.forEach(entry => {
      const count = reasonCounts.get(entry.reason) || 0;
      reasonCounts.set(entry.reason, count + 1);
    });

    console.log('📈 Revocation reasons:');
    for (const [reason, count] of reasonCounts.entries()) {
      console.log(`   ${reason}: ${count} times`);
    }

    // Get revocation statistics
    const stats = revocationManager.getRevocationStats();
    console.log('\n📊 Revocation Statistics:');
    console.log(`   Total revocations: ${stats.totalRevocations}`);
    console.log(`   Cascading revocations: ${stats.cascadingRevocations}`);
    console.log(`   Service-specific revocations: ${stats.serviceSpecificRevocations}`);
    console.log(`   Average child revocations: ${stats.averageChildRevocations.toFixed(2)}`);
    console.log(`   Notifications sent: ${stats.notificationsSent}`);

    // 7. Monitoring Dashboard
    console.log('\n7️⃣  Monitoring Dashboard Analysis\n');

    // Add audit entries to enhanced trail
    for (const entry of auditEntries) {
      await auditTrail.addAuditEntry(entry);
    }

    const dashboardMetrics = await dashboard.getMetrics();
    console.log('📊 Dashboard Metrics:');
    console.log(`   System health: ${dashboardMetrics.realTime.systemHealth}`);
    console.log(`   Active agents: ${dashboardMetrics.realTime.activeAgents}`);
    console.log(`   Alerts in last 24h: ${dashboardMetrics.realTime.alertsInLast24h}`);
    console.log(`   Total revocations: ${dashboardMetrics.historical.totalRevocations}`);
    console.log(`   Success rate: ${dashboardMetrics.historical.successRate.toFixed(1)}%`);

    // Get agent health overview
    const healthOverview = dashboard.getAgentHealthOverview();
    console.log('\n🏥 Agent Health Overview:');
    console.log(`   Total agents: ${healthOverview.totalAgents}`);
    console.log(`   Active agents: ${healthOverview.activeAgents}`);
    console.log(`   Revoked agents: ${healthOverview.revokedAgents}`);
    console.log(`   Recently revoked: ${healthOverview.recentlyRevoked}`);

    // 8. Compliance Report
    console.log('\n8️⃣  Compliance Report Generation\n');

    const complianceReport = auditTrail.generateComplianceReport({
      start: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
      end: new Date()
    });

    console.log('📋 Compliance Report Summary:');
    console.log(`   Compliance score: ${complianceReport.summary.complianceScore.toFixed(1)}%`);
    console.log(`   Successful revocations: ${complianceReport.summary.successfulRevocations}`);
    console.log(`   Failed revocations: ${complianceReport.summary.failedRevocations}`);
    console.log(`   Audit completeness: ${complianceReport.details.auditCompleteness.toFixed(1)}%`);
    console.log(`   Notification delivery: ${complianceReport.details.notificationDelivery.toFixed(1)}%`);

    if (complianceReport.recommendations.length > 0) {
      console.log('\n💡 Recommendations:');
      complianceReport.recommendations.forEach(rec => {
        console.log(`   • ${rec}`);
      });
    }

    if (complianceReport.violations.length > 0) {
      console.log('\n⚠️  Violations:');
      complianceReport.violations.forEach(violation => {
        console.log(`   ${violation.severity.toUpperCase()}: ${violation.description}`);
      });
    }

    // 9. Recovery Scenario
    console.log('\n9️⃣  Recovery Scenario: Re-enabling Access\n');

    console.log('🔄 Security audit complete - restoring engineering head access');
    
    // Create new credential for engineering head (simulating restoration)
    const newEngineeringCredential = await delegationManager.createDelegationCredential(
      ceoDID,
      ceoKeyPair,
      engineeringHead.did,
      `${engineeringHead.name} (Restored)`,
      {
        serviceDID: 'engineering-service',
        scopes: ['read:engineering', 'write:engineering', 'manage:engineering'], // Reduced privileges
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // Shorter term initially
      }
    );

    agentManager.addDelegationCredential(engineeringHead.did, newEngineeringCredential);
    
    console.log('✅ Engineering head access restored with reduced privileges');
    console.log('   New scopes: read:engineering, write:engineering, manage:engineering');
    console.log('   Duration: 7 days (probationary period)');

    // 10. Scenario 5: Bulk Operations
    console.log('\n🔟 Scenario 5: Bulk Revocation Operations\n');

    // Get all remaining engineering team members
    const remainingEngMembers = teamMembers.get('engineering').filter(member => 
      !revocationManager.isAgentRevoked(member.did)
    );

    console.log(`🎯 Bulk revoking ${remainingEngMembers.length} engineering team members`);

    const bulkResults = [];
    for (const member of remainingEngMembers) {
      const bulkResult = await revocationManager.revokeAgent({
        targetAgentDID: member.did,
        reason: 'Bulk operation - team restructuring',
        revokedBy: ceoDID,
        timestamp: new Date(),
        cascading: false
      });
      bulkResults.push({ member: member.name, success: bulkResult.success });
    }

    const successfulBulk = bulkResults.filter(r => r.success).length;
    console.log(`✅ Bulk operation results: ${successfulBulk}/${bulkResults.length} successful`);

    // 11. Final System State Report
    console.log('\n1️⃣1️⃣ Final System State Report\n');

    const finalMetrics = await dashboard.getMetrics();
    const finalStats = revocationManager.getRevocationStats();
    const finalHealthOverview = dashboard.getAgentHealthOverview();

    console.log('🏁 Final State Summary:');
    console.log(`   Total agents created: ${agentManager.getAllAgents().length}`);
    console.log(`   Currently active: ${finalHealthOverview.activeAgents}`);
    console.log(`   Total revoked: ${finalHealthOverview.revokedAgents}`);
    console.log(`   Total revocation operations: ${finalStats.totalRevocations}`);
    console.log(`   Cascading operations: ${finalStats.cascadingRevocations}`);
    console.log(`   Service-specific operations: ${finalStats.serviceSpecificRevocations}`);
    console.log(`   Overall success rate: ${((finalStats.totalRevocations - finalStats.averageChildRevocations) / finalStats.totalRevocations * 100).toFixed(1)}%`);

    // Department breakdown
    console.log('\n📊 Department Status:');
    for (const dept of departments) {
      const head = departmentHeads.get(dept);
      const members = teamMembers.get(dept);
      const headRevoked = revocationManager.isAgentRevoked(head.did);
      const membersRevoked = members.filter(m => revocationManager.isAgentRevoked(m.did)).length;
      
      console.log(`   ${dept}: Head ${headRevoked ? '❌' : '✅'}, Members ${membersRevoked}/${members.length} revoked`);
    }

    // Export audit trail for compliance
    console.log('\n📄 Exporting audit trail for compliance...');
    const auditExport = auditTrail.exportAuditData('json');
    console.log(`✅ Audit trail exported (${auditExport.length} characters)`);

    console.log('\n✅ Revocation scenarios example completed successfully!');
    console.log('\n📝 Summary of scenarios covered:');
    console.log('   1. ✅ Individual agent revocation');
    console.log('   2. ✅ Cascading revocation through delegation trees');
    console.log('   3. ✅ Service-specific revocation');
    console.log('   4. ✅ Emergency revocation procedures');
    console.log('   5. ✅ Bulk revocation operations');
    console.log('   6. ✅ Audit trail analysis and compliance reporting');
    console.log('   7. ✅ Monitoring dashboard integration');
    console.log('   8. ✅ Recovery and restoration procedures');

  } catch (error) {
    console.error('❌ Example failed:', error);
    throw error;
  } finally {
    // Cleanup
    dashboard.stop();
    await communicationManager.disconnectAll();
  }
}

// Run the example
if (require.main === module) {
  revocationScenariosExample()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('Example failed:', error);
      process.exit(1);
    });
}

export { revocationScenariosExample };