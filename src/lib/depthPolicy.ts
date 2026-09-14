import { ScanDepth, PlannedTest, SecurityCapability } from '../types';

export interface DepthConfiguration {
  depth: ScanDepth;
  name: string;
  badge: string;
  description: string;
  maxPlannedTests: number;
  validationPasses: number;
  timeoutSeconds: number;
  tokenBudgetMultiplier: number;
  includeExhaustiveSurfaces: boolean;
}

export const DEPTH_CONFIGS: Record<ScanDepth, DepthConfiguration> = {
  quick_surface: {
    depth: 'quick_surface',
    name: 'Brief / Quick Surface',
    badge: 'Fast Perimeter & High Priority',
    description: 'Rapid assessment focusing on high-priority attack vectors and essential validation.',
    maxPlannedTests: 6,
    validationPasses: 1,
    timeoutSeconds: 30,
    tokenBudgetMultiplier: 0.5,
    includeExhaustiveSurfaces: false,
  },
  deep_technical: {
    depth: 'deep_technical',
    name: 'Deep Technical Analysis',
    badge: 'Exhaustive Multi-Pass',
    description: 'Comprehensive audit executing all relevant capabilities, multi-pass validation, and full surface coverage.',
    maxPlannedTests: 25,
    validationPasses: 3,
    timeoutSeconds: 120,
    tokenBudgetMultiplier: 2.0,
    includeExhaustiveSurfaces: true,
  },
};

/**
 * Filters and prioritizes planned tests based on the selected depth budget.
 * Guarantees that Deep Technical mode includes AT LEAST as much test coverage as Quick Surface mode.
 */
export function applyDepthBudgetToPlan(tests: PlannedTest[], depth: ScanDepth): PlannedTest[] {
  const config = DEPTH_CONFIGS[depth] || DEPTH_CONFIGS.deep_technical;

  if (depth === 'quick_surface') {
    // In brief mode, select top high-priority tests up to maxPlannedTests
    const highPriority = tests.filter((t) => t.priority === 'high');
    const mediumPriority = tests.filter((t) => t.priority === 'medium');
    const lowPriority = tests.filter((t) => t.priority === 'low');

    const selected = [...highPriority, ...mediumPriority, ...lowPriority].slice(0, config.maxPlannedTests);
    return selected;
  }

  // In deep technical mode, return all planned tests up to the deep budget
  return tests.slice(0, config.maxPlannedTests);
}
