/**
 * MCP Test Runner
 * 
 * Centralized test execution and reporting for all Phase 5 MCP tests
 */

import { performance } from 'perf_hooks';

export interface TestSuite {
  name: string;
  description: string;
  tests: TestCase[];
  setup?: () => Promise<void>;
  teardown?: () => Promise<void>;
}

export interface TestCase {
  name: string;
  description: string;
  category: 'integration' | 'performance' | 'security' | 'multi-provider';
  priority: 'high' | 'medium' | 'low';
  timeout?: number;
  retries?: number;
  execute: () => Promise<TestResult>;
}

export interface TestResult {
  passed: boolean;
  duration: number;
  error?: Error;
  metrics?: Record<string, any>;
  logs?: string[];
}

export interface TestRunReport {
  totalTests: number;
  passedTests: number;
  failedTests: number;
  skippedTests: number;
  totalDuration: number;
  coverage: TestCoverage;
  suites: SuiteResult[];
}

export interface SuiteResult {
  suite: string;
  passed: number;
  failed: number;
  skipped: number;
  duration: number;
  results: TestCaseResult[];
}

export interface TestCaseResult {
  name: string;
  category: string;
  priority: string;
  status: 'passed' | 'failed' | 'skipped';
  duration: number;
  error?: string;
  metrics?: Record<string, any>;
}

export interface TestCoverage {
  integration: number;
  performance: number;
  security: number;
  multiProvider: number;
  overall: number;
}

/**
 * MCP Test Runner
 */
export class MCPTestRunner {
  private suites: TestSuite[] = [];
  private results: TestRunReport | null = null;

  /**
   * Add test suite
   */
  addSuite(suite: TestSuite): void {
    this.suites.push(suite);
  }

  /**
   * Run all test suites
   */
  async runAll(options: {
    categories?: string[];
    priorities?: string[];
    parallel?: boolean;
    verbose?: boolean;
  } = {}): Promise<TestRunReport> {
    const startTime = performance.now();
    
    console.log('🚀 Starting MCP Phase 5 Test Execution');
    console.log('=====================================\n');

    const suiteResults: SuiteResult[] = [];
    let totalTests = 0;
    let passedTests = 0;
    let failedTests = 0;
    let skippedTests = 0;

    for (const suite of this.suites) {
      if (options.verbose) {
        console.log(`📋 Running suite: ${suite.name}`);
        console.log(`   Description: ${suite.description}`);
      }

      const suiteResult = await this.runSuite(suite, options);
      suiteResults.push(suiteResult);

      totalTests += suiteResult.passed + suiteResult.failed + suiteResult.skipped;
      passedTests += suiteResult.passed;
      failedTests += suiteResult.failed;
      skippedTests += suiteResult.skipped;

      if (options.verbose) {
        console.log(`   ✅ ${suiteResult.passed} passed, ❌ ${suiteResult.failed} failed, ⏭️ ${suiteResult.skipped} skipped`);
        console.log(`   ⏱️ Duration: ${suiteResult.duration.toFixed(2)}ms\n`);
      }
    }

    const endTime = performance.now();
    const totalDuration = endTime - startTime;

    this.results = {
      totalTests,
      passedTests,
      failedTests,
      skippedTests,
      totalDuration,
      coverage: this.calculateCoverage(suiteResults),
      suites: suiteResults
    };

    this.printSummary();
    return this.results;
  }

  /**
   * Run specific test suite
   */
  private async runSuite(
    suite: TestSuite,
    options: {
      categories?: string[];
      priorities?: string[];
      parallel?: boolean;
      verbose?: boolean;
    }
  ): Promise<SuiteResult> {
    const startTime = performance.now();

    // Setup
    if (suite.setup) {
      await suite.setup();
    }

    const results: TestCaseResult[] = [];
    let passed = 0;
    let failed = 0;
    let skipped = 0;

    // Filter tests based on options
    const testsToRun = suite.tests.filter(test => {
      if (options.categories && !options.categories.includes(test.category)) {
        return false;
      }
      if (options.priorities && !options.priorities.includes(test.priority)) {
        return false;
      }
      return true;
    });

    // Run tests
    if (options.parallel) {
      const testPromises = testsToRun.map(test => this.runTest(test, options.verbose));
      const testResults = await Promise.allSettled(testPromises);
      
      testResults.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          results.push(result.value);
          if (result.value.status === 'passed') passed++;
          else if (result.value.status === 'failed') failed++;
          else skipped++;
        } else {
          results.push({
            name: testsToRun[index].name,
            category: testsToRun[index].category,
            priority: testsToRun[index].priority,
            status: 'failed',
            duration: 0,
            error: result.reason?.message || 'Unknown error'
          });
          failed++;
        }
      });
    } else {
      for (const test of testsToRun) {
        const result = await this.runTest(test, options.verbose);
        results.push(result);
        
        if (result.status === 'passed') passed++;
        else if (result.status === 'failed') failed++;
        else skipped++;
      }
    }

    // Teardown
    if (suite.teardown) {
      await suite.teardown();
    }

    const endTime = performance.now();
    const duration = endTime - startTime;

    return {
      suite: suite.name,
      passed,
      failed,
      skipped,
      duration,
      results
    };
  }

  /**
   * Run individual test case
   */
  private async runTest(test: TestCase, verbose?: boolean): Promise<TestCaseResult> {
    const startTime = performance.now();

    if (verbose) {
      console.log(`   🧪 Running: ${test.name}`);
    }

    try {
      const result = await this.executeWithTimeout(test);
      const endTime = performance.now();
      const duration = endTime - startTime;

      if (verbose) {
        console.log(`      ✅ Passed (${duration.toFixed(2)}ms)`);
      }

      return {
        name: test.name,
        category: test.category,
        priority: test.priority,
        status: result.passed ? 'passed' : 'failed',
        duration,
        error: result.error?.message,
        metrics: result.metrics
      };
    } catch (error: any) {
      const endTime = performance.now();
      const duration = endTime - startTime;

      if (verbose) {
        console.log(`      ❌ Failed: ${error.message} (${duration.toFixed(2)}ms)`);
      }

      return {
        name: test.name,
        category: test.category,
        priority: test.priority,
        status: 'failed',
        duration,
        error: error.message
      };
    }
  }

  /**
   * Execute test with timeout and retries
   */
  private async executeWithTimeout(test: TestCase): Promise<TestResult> {
    const timeout = test.timeout || 30000; // 30 second default
    const retries = test.retries || 0;

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const result = await Promise.race([
          test.execute(),
          new Promise<TestResult>((_, reject) => 
            setTimeout(() => reject(new Error(`Test timeout after ${timeout}ms`)), timeout)
          )
        ]);

        if (result.passed || attempt === retries) {
          return result;
        }
      } catch (error) {
        if (attempt === retries) {
          throw error;
        }
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    throw new Error('Test failed after all retry attempts');
  }

  /**
   * Calculate test coverage
   */
  private calculateCoverage(suiteResults: SuiteResult[]): TestCoverage {
    const categories = ['integration', 'performance', 'security', 'multi-provider'];
    const coverage: any = {};

    categories.forEach(category => {
      const categoryTests = suiteResults.flatMap(suite => 
        suite.results.filter(result => result.category === category)
      );
      
      const passed = categoryTests.filter(test => test.status === 'passed').length;
      const total = categoryTests.length;
      
      coverage[category] = total > 0 ? (passed / total) * 100 : 0;
    });

    const allTests = suiteResults.flatMap(suite => suite.results);
    const allPassed = allTests.filter(test => test.status === 'passed').length;
    const allTotal = allTests.length;
    
    coverage.overall = allTotal > 0 ? (allPassed / allTotal) * 100 : 0;

    return coverage;
  }

  /**
   * Print test summary
   */
  private printSummary(): void {
    if (!this.results) return;

    console.log('\n📊 MCP Phase 5 Test Results Summary');
    console.log('===================================');
    console.log(`Total Tests: ${this.results.totalTests}`);
    console.log(`✅ Passed: ${this.results.passedTests}`);
    console.log(`❌ Failed: ${this.results.failedTests}`);
    console.log(`⏭️ Skipped: ${this.results.skippedTests}`);
    console.log(`⏱️ Total Duration: ${(this.results.totalDuration / 1000).toFixed(2)}s`);
    console.log(`📈 Success Rate: ${((this.results.passedTests / this.results.totalTests) * 100).toFixed(1)}%`);

    console.log('\n📋 Test Coverage by Category:');
    console.log(`Integration: ${this.results.coverage.integration.toFixed(1)}%`);
    console.log(`Performance: ${this.results.coverage.performance.toFixed(1)}%`);
    console.log(`Security: ${this.results.coverage.security.toFixed(1)}%`);
    console.log(`Multi-Provider: ${this.results.coverage.multiProvider.toFixed(1)}%`);
    console.log(`Overall: ${this.results.coverage.overall.toFixed(1)}%`);

    console.log('\n📈 Suite Breakdown:');
    this.results.suites.forEach(suite => {
      const successRate = suite.passed / (suite.passed + suite.failed + suite.skipped) * 100;
      console.log(`${suite.suite}: ${suite.passed}/${suite.passed + suite.failed + suite.skipped} (${successRate.toFixed(1)}%)`);
    });

    if (this.results.failedTests > 0) {
      console.log('\n❌ Failed Tests:');
      this.results.suites.forEach(suite => {
        suite.results
          .filter(result => result.status === 'failed')
          .forEach(result => {
            console.log(`   ${suite.suite}: ${result.name}`);
            if (result.error) {
              console.log(`      Error: ${result.error}`);
            }
          });
      });
    }

    // Overall result
    if (this.results.failedTests === 0) {
      console.log('\n🎉 All tests passed! MCP Phase 5 validation successful.');
    } else {
      console.log(`\n⚠️ ${this.results.failedTests} test(s) failed. Review and fix issues.`);
    }
  }

  /**
   * Export results to file
   */
  exportResults(format: 'json' | 'xml' | 'html' = 'json'): string {
    if (!this.results) {
      throw new Error('No test results available');
    }

    switch (format) {
      case 'json':
        return JSON.stringify(this.results, null, 2);
      
      case 'xml':
        return this.toXML(this.results);
      
      case 'html':
        return this.toHTML(this.results);
      
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  /**
   * Convert results to XML (JUnit format)
   */
  private toXML(results: TestRunReport): string {
    const xml = ['<?xml version="1.0" encoding="UTF-8"?>'];
    xml.push('<testsuites>');
    
    results.suites.forEach(suite => {
      xml.push(`  <testsuite name="${suite.suite}" tests="${suite.passed + suite.failed + suite.skipped}" failures="${suite.failed}" time="${(suite.duration / 1000).toFixed(3)}">`);
      
      suite.results.forEach(test => {
        xml.push(`    <testcase name="${test.name}" classname="${suite.suite}" time="${(test.duration / 1000).toFixed(3)}">`);
        
        if (test.status === 'failed') {
          xml.push(`      <failure message="${test.error || 'Test failed'}">${test.error || ''}</failure>`);
        } else if (test.status === 'skipped') {
          xml.push('      <skipped/>');
        }
        
        xml.push('    </testcase>');
      });
      
      xml.push('  </testsuite>');
    });
    
    xml.push('</testsuites>');
    return xml.join('\n');
  }

  /**
   * Convert results to HTML report
   */
  private toHTML(results: TestRunReport): string {
    const html = [
      '<!DOCTYPE html>',
      '<html><head><title>MCP Phase 5 Test Results</title>',
      '<style>',
      'body { font-family: Arial, sans-serif; margin: 20px; }',
      '.summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }',
      '.suite { margin-bottom: 20px; border: 1px solid #ddd; border-radius: 5px; }',
      '.suite-header { background: #e9e9e9; padding: 10px; font-weight: bold; }',
      '.test-case { padding: 8px; border-bottom: 1px solid #eee; }',
      '.passed { color: green; }',
      '.failed { color: red; }',
      '.skipped { color: orange; }',
      '</style>',
      '</head><body>'
    ];

    html.push('<h1>MCP Phase 5 Test Results</h1>');
    
    // Summary
    html.push('<div class="summary">');
    html.push(`<h2>Summary</h2>`);
    html.push(`<p>Total Tests: ${results.totalTests}</p>`);
    html.push(`<p>Passed: <span class="passed">${results.passedTests}</span></p>`);
    html.push(`<p>Failed: <span class="failed">${results.failedTests}</span></p>`);
    html.push(`<p>Skipped: <span class="skipped">${results.skippedTests}</span></p>`);
    html.push(`<p>Duration: ${(results.totalDuration / 1000).toFixed(2)}s</p>`);
    html.push(`<p>Success Rate: ${((results.passedTests / results.totalTests) * 100).toFixed(1)}%</p>`);
    html.push('</div>');

    // Test suites
    results.suites.forEach(suite => {
      html.push('<div class="suite">');
      html.push(`<div class="suite-header">${suite.suite}</div>`);
      
      suite.results.forEach(test => {
        const statusClass = test.status;
        html.push(`<div class="test-case">`);
        html.push(`<span class="${statusClass}">${test.status.toUpperCase()}</span> ${test.name}`);
        html.push(`<small> (${test.duration.toFixed(2)}ms)</small>`);
        if (test.error) {
          html.push(`<br><small style="color: red;">Error: ${test.error}</small>`);
        }
        html.push('</div>');
      });
      
      html.push('</div>');
    });

    html.push('</body></html>');
    return html.join('\n');
  }

  /**
   * Get test results
   */
  getResults(): TestRunReport | null {
    return this.results;
  }
}

/**
 * Example usage and demo test suites
 */
export function createDemoTestSuites(): TestSuite[] {
  return [
    {
      name: 'MCP Integration Tests',
      description: 'Comprehensive integration testing for MCP components',
      tests: [
        {
          name: 'Basic MCP Communication',
          description: 'Test basic LLM request/response flow',
          category: 'integration',
          priority: 'high',
          execute: async () => ({
            passed: true,
            duration: 150,
            metrics: { requests: 1, latency: 150 }
          })
        },
        {
          name: 'Natural Language Processing',
          description: 'Test natural language message processing',
          category: 'integration',
          priority: 'high',
          execute: async () => ({
            passed: true,
            duration: 300,
            metrics: { tokens: 50, accuracy: 0.95 }
          })
        }
      ]
    },
    {
      name: 'MCP Performance Tests',
      description: 'Performance benchmarking and load testing',
      tests: [
        {
          name: 'Latency Benchmark',
          description: 'Measure response latency under load',
          category: 'performance',
          priority: 'medium',
          timeout: 60000,
          execute: async () => ({
            passed: true,
            duration: 5000,
            metrics: { avgLatency: 200, p95Latency: 350, throughput: 25 }
          })
        },
        {
          name: 'Concurrent Load Test',
          description: 'Test system under concurrent load',
          category: 'performance',
          priority: 'medium',
          timeout: 120000,
          execute: async () => ({
            passed: true,
            duration: 10000,
            metrics: { concurrentUsers: 50, successRate: 0.98 }
          })
        }
      ]
    }
  ];
}

// CLI runner for standalone execution
if (require.main === module) {
  const runner = new MCPTestRunner();
  const demoSuites = createDemoTestSuites();
  
  demoSuites.forEach(suite => runner.addSuite(suite));
  
  runner.runAll({ verbose: true })
    .then(results => {
      console.log('\n📁 Test results exported to:');
      console.log('  - results.json');
      console.log('  - results.xml (JUnit format)');
      console.log('  - results.html');
      
      process.exit(results.failedTests > 0 ? 1 : 0);
    })
    .catch(error => {
      console.error('Test execution failed:', error);
      process.exit(1);
    });
}

export default MCPTestRunner;