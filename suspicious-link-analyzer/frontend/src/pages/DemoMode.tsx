import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Sparkles, Play, ShieldAlert, Loader2, ArrowRight } from 'lucide-react';
import { api } from '@/services/api';
import ThreatBadge from '@/components/ThreatBadge';
import type { DemoScenario, ThreatLevel } from '@/types';

export default function DemoMode() {
  const navigate = useNavigate();
  const [scenarios, setScenarios] = useState<DemoScenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [runningId, setRunningId] = useState<string | null>(null);

  useEffect(() => {
    const fetchScenarios = async () => {
      try {
        setLoading(true);
        const res = await api.getScenarios();
        setScenarios(res.data);
      } catch (err) {
        console.error('Failed to load demo scenarios:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchScenarios();
  }, []);

  const handleRunScenario = async (scenarioId: string) => {
    try {
      setRunningId(scenarioId);
      const res = await api.runDemo(scenarioId);
      navigate(`/scan/${res.data.id}`);
    } catch (err) {
      alert('Failed to execute demo simulation');
    } finally {
      setRunningId(null);
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-4 py-10 space-y-8">
      {/* Notice Banner */}
      <div className="p-4 rounded-xl bg-purple-950/60 border border-purple-800 flex items-start gap-3">
        <Sparkles className="w-5 h-5 text-purple-400 mt-0.5 shrink-0" />
        <div className="text-xs text-purple-200 space-y-1">
          <p className="font-bold text-sm text-purple-100">Demonstration & Evaluation Environment</p>
          <p>
            Demo mode showcases the multi-provider aggregation logic, scoring models, and user workflow using simulated threat scenarios. 
            No live external API keys are used for these scenarios.
          </p>
        </div>
      </div>

      <div className="space-y-2">
        <h1 className="text-3xl font-extrabold text-white">Preconfigured Demo Scenarios</h1>
        <p className="text-sm text-slate-400">
          Select any cybersecurity test case below to inspect how the platform analyzes, normalizes, and classifies different URL types.
        </p>
      </div>

      {loading ? (
        <div className="py-16 text-center text-slate-400">
          <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-2" />
          Loading scenarios...
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {scenarios.map((sc) => (
            <div
              key={sc.id}
              className="p-6 rounded-2xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-4"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-base font-bold text-white">{sc.name}</h3>
                  <ThreatBadge level={sc.expected_threat_level as ThreatLevel} />
                </div>
                <div className="text-xs font-mono text-cyan-400 break-all bg-slate-950 p-2 rounded border border-slate-800">
                  {sc.url}
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{sc.description}</p>
              </div>

              <button
                disabled={runningId === sc.id}
                onClick={() => handleRunScenario(sc.id)}
                className="w-full inline-flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition disabled:opacity-50"
              >
                {runningId === sc.id ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" /> Simulating...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" /> Execute Demo Scan
                  </>
                )}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
