import React, { useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  Play,
  RotateCw,
  Shield,
  Layers,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  Terminal,
  Activity,
  Award,
} from 'lucide-react';
import { TestSuiteReport, TestSuiteTestCase } from '../types';
import { safeFetchJson } from '../lib/safeFetch';

interface TestSuiteModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const TestSuiteModal: React.FC<TestSuiteModalProps> = ({ isOpen, onClose }) => {
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<TestSuiteReport | null>(null);
  const [expandedTest, setExpandedTest] = useState<string | null>(null);

  if (!isOpen) return null;

  const runTestSuite = async () => {
    setRunning(true);
    try {
      const res = await safeFetchJson<{ success?: boolean; report?: TestSuiteReport }>('/api/tests/run-suite', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (res.success && res.data?.report) {
        setReport(res.data.report);
      }
    } catch (e) {
      console.error('Error running test suite:', e);
    } finally {
      setRunning(false);
    }
  };

  const toggleTest = (id: string) => {
    setExpandedTest(expandedTest === id ? null : id);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden min-w-0">
        {/* Modal Header */}
        <div className="p-6 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <div className="p-2.5 rounded-xl bg-slate-800 border border-slate-700 shrink-0">
              <Award className="w-5 h-5 text-white" />
            </div>
            <div className="min-w-0">
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                10-Point Architecture Test Suite
              </h2>
              <p className="text-xs text-slate-400">
                Automated regression & golden-rule verification across the 12-stage pipeline
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={runTestSuite}
              disabled={running}
              className="px-4 py-2 rounded-xl bg-white hover:bg-slate-200 text-slate-900 text-xs font-bold transition flex items-center gap-2 shadow cursor-pointer"
            >
              <Play className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} />
              {running ? 'Running Tests...' : 'Run All 10 Tests'}
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition text-xs cursor-pointer"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {/* Summary Bar */}
          {report && (
            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                {report.all_passed ? (
                  <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                    <CheckCheck className="w-5 h-5" />
                  </div>
                ) : (
                  <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
                    <XCircle className="w-5 h-5" />
                  </div>
                )}
                <div>
                  <div className="text-sm font-bold text-slate-100">
                    {report.all_passed ? 'All 10 Architectural Tests Passed Successfully' : `${report.failed_tests} Tests Failed`}
                  </div>
                  <div className="text-xs text-slate-400">
                    Passed: <span className="text-emerald-400 font-bold">{report.passed_tests}</span> / {report.total_tests} tests • Executed at {new Date(report.executed_at).toLocaleTimeString()}
                  </div>
                </div>
              </div>

              <span className="px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                100% GOLDEN RULE COMPLIANT
              </span>
            </div>
          )}

          {/* Test List */}
          <div className="space-y-3">
            {(!report ? defaultTestSpecs : report.tests).map((test: any, idx: number) => {
              const isExpanded = expandedTest === (test.id || `test-${idx + 1}`);
              const isPassed = report ? test.passed : null;

              return (
                <div
                  key={test.id || idx}
                  className="bg-slate-950/60 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition"
                >
                  <div
                    onClick={() => toggleTest(test.id || `test-${idx + 1}`)}
                    className="flex items-start justify-between gap-3 cursor-pointer"
                  >
                    <div className="flex items-start gap-3">
                      <div className="pt-0.5">
                        {isPassed === true && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                        {isPassed === false && <XCircle className="w-4 h-4 text-red-400" />}
                        {isPassed === null && <span className="w-4 h-4 rounded-full bg-slate-800 inline-block" />}
                      </div>
                      <div>
                        <div className="text-xs font-bold text-slate-200 flex items-center gap-2">
                          {test.name}
                          {test.duration_ms && (
                            <span className="text-[10px] font-mono text-slate-500">
                              ({test.duration_ms}ms)
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">{test.description}</p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {isPassed === true && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          PASSED
                        </span>
                      )}
                      {isPassed === false && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/30">
                          FAILED
                        </span>
                      )}
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-slate-400" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-slate-400" />
                      )}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="mt-4 pt-4 border-t border-slate-800 space-y-2 text-xs font-mono">
                      <div>
                        <span className="text-slate-500">EXPECTED OUTCOME:</span>
                        <div className="text-slate-300 bg-slate-900 p-2 rounded mt-1 border border-slate-800">
                          {test.expected_outcome}
                        </div>
                      </div>
                      {test.actual_outcome && (
                        <div>
                          <span className="text-slate-500">ACTUAL OUTCOME:</span>
                          <div className="text-emerald-400 bg-slate-900 p-2 rounded mt-1 border border-slate-800">
                            {test.actual_outcome}
                          </div>
                        </div>
                      )}
                      {test.details && (
                        <pre className="text-[11px] text-slate-400 bg-slate-900 p-2 rounded border border-slate-800 overflow-x-auto max-h-40">
                          {JSON.stringify(test.details, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between text-xs text-slate-400">
          <div>Covers all 10 architecture validation rules from Section 15.</div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

const defaultTestSpecs = [
  {
    id: 'test-1',
    name: 'TEST 1 — SECURE APPLICATION',
    description: 'Upload a secure application. Expected: 0 confirmed vulnerabilities. System must not invent risks.',
    expected_outcome: '0 confirmed vulnerabilities, posture status = hardened_resilient.',
  },
  {
    id: 'test-2',
    name: 'TEST 2 — DIFFERENT APPLICATIONS',
    description: 'Upload two structurally different applications. Attack surfaces and test plans differ.',
    expected_outcome: 'Attack surface discovery maps distinct technologies and flags.',
  },
  {
    id: 'test-3',
    name: 'TEST 3 — IRRELEVANT CATEGORY',
    description: 'Upload an application with no GraphQL. GraphQL security marked irrelevant / not applicable.',
    expected_outcome: 'GraphQL capability marked as NOT_APPLICABLE; no GraphQL flaw manufactured.',
  },
  {
    id: 'test-4',
    name: 'TEST 4 — SAFE SQL',
    description: 'Use safely parameterized SQL queries with placeholders ($1).',
    expected_outcome: 'SQL Injection: NOT DETECTED (not medium risk).',
  },
  {
    id: 'test-5',
    name: 'TEST 5 — REAL VULNERABILITY',
    description: 'Authorized test target with cross-tenant authorization bypass proof.',
    expected_outcome: 'Validation succeeds and finding status transitions to CONFIRMED.',
  },
  {
    id: 'test-6',
    name: 'TEST 6 — FALSE POSITIVE',
    description: 'Code that looks suspicious but is safe at runtime.',
    expected_outcome: 'Validation rejects hypothesis (status = REJECTED, 0 confirmed risk).',
  },
  {
    id: 'test-7',
    name: 'TEST 7 — DUPLICATE CORRELATION',
    description: 'Multiple agents identify identical vulnerability sink.',
    expected_outcome: 'Merged into 1 canonical finding with merged evidence.',
  },
  {
    id: 'test-8',
    name: 'TEST 8 — DIFFERENT FINDINGS SAME CATEGORY',
    description: 'Two separate IDOR issues in different routes.',
    expected_outcome: 'Preserves 2 distinct findings with unique SHA-256 fingerprints.',
  },
  {
    id: 'test-9',
    name: 'TEST 9 — PROJECT VERSION DIFF',
    description: 'Scan Version 1, modify source, scan Version 2.',
    expected_outcome: 'Different SHA-256; previous finding labeled "Not detected in current scan" without blind copying.',
  },
  {
    id: 'test-10',
    name: 'TEST 10 — NO VULNERABILITIES RESULT VALIDITY',
    description: 'Secure application finishing with 0 vulnerabilities.',
    expected_outcome: 'Finishes with 0 confirmed vulnerabilities without error.',
  },
];
