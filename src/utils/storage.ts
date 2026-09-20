import { AnalysisResult } from '../types';

const HISTORY_KEY = 'online_safety_guard_history_v1';

export function getScanHistory(): AnalysisResult[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch (e) {
    console.error('Failed to load history', e);
    return [];
  }
}

export function saveScanToHistory(scan: AnalysisResult): void {
  try {
    const history = getScanHistory();
    const updated = [scan, ...history.filter(item => item.id !== scan.id)].slice(0, 30);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
  } catch (e) {
    console.error('Failed to save to history', e);
  }
}

export function clearScanHistory(): void {
  try {
    localStorage.removeItem(HISTORY_KEY);
  } catch (e) {
    console.error('Failed to clear history', e);
  }
}
