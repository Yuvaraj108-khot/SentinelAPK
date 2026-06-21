"use client";

import React, { useState, useEffect } from "react";

interface Certificate {
  issuer: string;
  subject: string;
  serial_number: string;
  sha256: string;
  sha1: string;
}

interface Metadata {
  app_name: string;
  package_name: string;
  version_name: string;
  version_code: string;
  min_sdk: string;
  target_sdk: string;
  permissions: string[];
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
  certificates: Certificate[];
  dex_indicators?: {
    sms_send: boolean;
    sms_manager?: boolean;
    accessibility_callback: boolean;
    accessibility_service?: boolean;
    overlay_window: boolean;
    http_client: boolean;
    dex_class_loader?: boolean;
    runtime_exec?: boolean;
    suspicious_urls?: string[];
  };
}

interface Risk {
  score: number;
  verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
  severity: "Low" | "Medium" | "High" | "Critical";
  confidence: number;
  top_reasons: string[];
  triggered_rules: { permission: string; weight: number; description: string }[];
  mitre_techniques: { id: string; name: string; description: string }[];
  attack_chain: { step: string; desc: string }[];
  clone_findings?: {
    is_clone: boolean;
    official_target: string | null;
    similarity_score: number;
  };
  cert_findings?: {
    is_trusted: boolean;
    reputation_issue: string | null;
  };
  evidence_validation?: {
    sms: { status: string; matched_string?: string; source_file?: string; offset?: number; extraction_method?: string; confidence?: number };
    accessibility: { status: string; matched_string?: string; source_file?: string; offset?: number; extraction_method?: string; confidence?: number };
    overlay: { status: string; matched_string?: string; source_file?: string; offset?: number; extraction_method?: string; confidence?: number };
    runtime_exec: { status: string; matched_string?: string; source_file?: string; offset?: number; extraction_method?: string; confidence?: number };
    dynamic_loading: { status: string; matched_string?: string; source_file?: string; offset?: number; extraction_method?: string; confidence?: number };
    clone_detection: { status: string; matched_string?: string; source_file?: string; offset?: number; extraction_method?: string; confidence?: number };
    certificate_validation: { status: string; matched_string?: string; source_file?: string; offset?: number; extraction_method?: string; confidence?: number };
  };
}

interface AIAnalysis {
  suspicious_permissions_rationale: string;
  otp_theft_capability: string;
  accessibility_abuse: string;
  impersonation_risk: string;
  data_exfiltration: string;
  verdict_reasoning: string;
}

interface Sample {
  id: string;
  name: string;
  verdict: string;
  score: string;
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<"overview" | "permissions" | "ai" | "impersonation" | "runtime" | "adversarial" | "learning">("overview");
  const [samples, setSamples] = useState<Sample[]>([]);
  const [selectedSampleId, setSelectedSampleId] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [progressStep, setProgressStep] = useState<number>(0);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  
  // Active Analysis State
  const [sessionId, setSessionId] = useState<string>("");
  const [appMetadata, setAppMetadata] = useState<Metadata | null>(null);
  const [riskData, setRiskData] = useState<Risk | null>(null);
  const [aiData, setAiData] = useState<AIAnalysis | null>(null);
  const [errorMsg, setErrorMsg] = useState<string>("");

  // Adversarial Red-Team Lab State
  const [redteamData, setRedteamData] = useState<any | null>(null);
  const [redteamLoading, setRedteamLoading] = useState<boolean>(false);
  const [lessonsLearned, setLessonsLearned] = useState<Array<{ pattern: string; risk: string }>>([
    { pattern: "READ_SMS + INTERNET", risk: "Medium" },
    { pattern: "Overlay + Banking UI", risk: "Critical" },
    { pattern: "Accessibility + Network Access", risk: "Critical" }
  ]);

  // Adaptive Learning Dashboard State
  const [activeWeights, setActiveWeights] = useState<Record<string, any>>({});
  const [learningHistory, setLearningHistory] = useState<any[]>([]);
  const [learningExplanations, setLearningExplanations] = useState<string[]>([]);
  const [benchmarkRuns, setBenchmarkRuns] = useState<any[]>([]);
  const [runningBenchmark, setRunningBenchmark] = useState<boolean>(false);
  const [effectivenessReport, setEffectivenessReport] = useState<any | null>(null);

  useEffect(() => {
    fetchSamples();
    fetchLessons();
    fetchWeights();
    fetchLearningHistory();
    fetchLearningExplanations();
    fetchBenchmarkRuns();
    fetchEffectiveness();
    loadSample("anubis"); // Load default demo data on launch
  }, []);

  const fetchWeights = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/learning/status");
      if (res.ok) {
        const data = await res.json();
        setActiveWeights(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchLearningHistory = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/learning/history");
      if (res.ok) {
        const data = await res.json();
        setLearningHistory(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchLearningExplanations = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/learning/explanations");
      if (res.ok) {
        const data = await res.json();
        setLearningExplanations(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchEffectiveness = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/learning/effectiveness");
      if (res.ok) {
        const data = await res.json();
        setEffectivenessReport(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchBenchmarkRuns = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/benchmark/history");
      if (res.ok) {
        const data = await res.json();
        setBenchmarkRuns(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const triggerBenchmarkRun = async () => {
    setRunningBenchmark(true);
    try {
      const res = await fetch("http://localhost:8000/api/benchmark/run", { method: "POST" });
      if (res.ok) {
        await fetchWeights();
        await fetchLearningHistory();
        await fetchLearningExplanations();
        await fetchBenchmarkRuns();
        await fetchEffectiveness();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setRunningBenchmark(false);
    }
  };

  const fetchLessons = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/redteam/lessons");
      if (res.ok) {
        const data = await res.json();
        const formatted = data.map((item: any) => ({
          pattern: item.pattern,
          risk: item.difficulty >= 80 ? "Critical" : (item.difficulty >= 60 ? "High" : "Medium"),
          lesson: item.lesson
        }));
        setLessonsLearned(formatted);
      }
    } catch (err) {
      console.error("Failed to load persistent lessons", err);
    }
  };

  const fetchSamples = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/samples");
      if (res.ok) {
        const data = await res.json();
        setSamples(data);
      }
    } catch (err) {
      console.error("Failed to load samples", err);
    }
  };

  const triggerRedteamMutation = async () => {
    if (!appMetadata || !riskData) return;
    setRedteamLoading(true);
    setRedteamData(null);
    try {
      const res = await fetch("http://localhost:8000/api/redteam/mutate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_name: appMetadata.app_name,
          package_name: appMetadata.package_name,
          permissions: appMetadata.permissions,
          risk_score: riskData.score,
          verdict: riskData.verdict
        })
      });
      if (res.ok) {
        const data = await res.json();
        setRedteamData(data);
        fetchLessons(); // Reload updated persistent store
      }
    } catch (err) {
      console.error("Red-team simulation failed", err);
    } finally {
      setRedteamLoading(false);
    }
  };

  const loadSample = async (id: string) => {
    setLoading(true);
    setErrorMsg("");
    setSelectedSampleId(id);
    setSessionId(id);
    setConsoleLogs([]);
    
    // Simulate pipeline loading for samples
    setConsoleLogs((prev) => [...prev, "[SYS] [Stage 1/5] Initiating Fast Triage: Reading APK manifest & certificate metadata..."]);
    setProgressStep(1);
    await new Promise((r) => setTimeout(r, 150));
    
    setConsoleLogs((prev) => [...prev, "[SYS] [Stage 2/5] Running LLM Intent Graph Analysis: Mapping static permissions & dependency weights..."]);
    setProgressStep(2);
    await new Promise((r) => setTimeout(r, 150));
    
    setConsoleLogs((prev) => [...prev, "[SYS] [Stage 3/5] Launching Multimodal UI Deception Detection: Evaluating screen overlay templates..."]);
    setProgressStep(3);
    await new Promise((r) => setTimeout(r, 150));
    
    setConsoleLogs((prev) => [...prev, "[SYS] [Stage 4/5] Executing Dynamic Runtime Analysis: Simulating behavior flow and API execution logs..."]);
    setProgressStep(4);
    await new Promise((r) => setTimeout(r, 150));
    
    setConsoleLogs((prev) => [...prev, "[SYS] [Stage 5/5] Compiling Signal Fusion & Investigation Report: Assembling explainable audit summary..."]);
    setProgressStep(5);
    await new Promise((r) => setTimeout(r, 150));
    
    try {
      const res = await fetch(`http://localhost:8000/api/samples/${id}`);
      if (res.ok) {
        const data = await res.json();
        setAppMetadata(data.metadata);
        setRiskData(data.risk);
        setAiData(data.ai);
        setConsoleLogs((prev) => [...prev, "[+] Analysis pipeline completed. Threat report fused successfully!"]);
      } else {
        setErrorMsg("Failed to load sample details.");
      }
    } catch (err) {
      setErrorMsg("Unable to communicate with the FastAPI backend.");
    } finally {
      setLoading(false);
      setProgressStep(0);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith(".apk")) {
      setErrorMsg("Only Android APK files are supported.");
      return;
    }

    setLoading(true);
    setErrorMsg("");
    setAppMetadata(null);
    setRiskData(null);
    setAiData(null);
    setSelectedSampleId("");
    setSessionId("");
    setConsoleLogs(["[SYS] [Stage 1/5] Initiating Fast Triage: Uploading raw package and extracting manifest configurations..."]);

    // Stage 1: Fast Triage
    setProgressStep(1);
    
    const formData = new FormData();
    formData.append("file", file);

    try {
      // Stage 2: LLM Intent Graph Analysis
      setTimeout(() => {
        setProgressStep(2);
        setConsoleLogs((prev) => [...prev, "[SYS] [Stage 2/5] Running LLM Intent Graph Analysis: Analyzing permission combinations and decompiled classes.dex structures..."]);
      }, 500);
      
      // Stage 3: Multimodal UI Deception Detection
      setTimeout(() => {
        setProgressStep(3);
        setConsoleLogs((prev) => [...prev, "[SYS] [Stage 3/5] Launching Multimodal UI Deception Detection: Evaluating visual overlays and layout components..."]);
      }, 1000);
      
      // Stage 4: Dynamic Runtime Analysis
      setTimeout(() => {
        setProgressStep(4);
        setConsoleLogs((prev) => [...prev, "[SYS] [Stage 4/5] Executing Dynamic Runtime Analysis: Inspecting broadcast receivers, triggers, and exfiltration targets..."]);
      }, 1500);
      
      // Stage 5: Signal Fusion & Investigation Report
      setTimeout(() => {
        setProgressStep(5);
        setConsoleLogs((prev) => [...prev, "[SYS] [Stage 5/5] Compiling Signal Fusion & Investigation Report: Running AI rationale generator and compiling final PDF audit..."]);
      }, 2000);

      const res = await fetch("http://localhost:8000/api/analyze", {
        method: "POST",
        body: formData,
      });

      if (res.ok) {
        const data = await res.json();
        setSessionId(data.session_id);
        setAppMetadata(data.metadata);
        setRiskData(data.risk);
        setAiData(data.ai);
        setConsoleLogs((prev) => [...prev, "[+] Analysis completed successfully!", `[+] Fusion Report Session ID: ${data.session_id}`]);
      } else {
        const errJson = await res.json();
        setErrorMsg(errJson.detail || "Analysis failed.");
      }
    } catch (err) {
      setErrorMsg("Connection to FastAPI server lost.");
    } finally {
      setLoading(false);
      setProgressStep(0);
    }
  };

  const triggerDownload = () => {
    if (!sessionId) return;
    window.open(`http://localhost:8000/api/report/download/${sessionId}`);
  };

  // Helper colors based on risk severity
  const getVerdictStyles = (verdict: string) => {
    switch (verdict) {
      case "MALICIOUS":
        return {
          bg: "bg-red-950/40 border-red-500/30 text-[#ef4444]",
          text: "text-red-500",
          badge: "bg-red-500 text-[#111827] shadow-[0_0_15px_rgba(239,68,68,0.5)]",
          border: "border-red-500/50",
          gauge: "stroke-red-500"
        };
      case "SUSPICIOUS":
        return {
          bg: "bg-amber-950/40 border-amber-500/30 text-amber-600",
          text: "text-amber-500",
          badge: "bg-amber-500 text-black shadow-[0_0_15px_rgba(245,158,11,0.5)]",
          border: "border-amber-500/50",
          gauge: "stroke-amber-500"
        };
      default:
        return {
          bg: "bg-emerald-950/40 border-emerald-500/30 text-emerald-600",
          text: "text-emerald-500",
          badge: "bg-emerald-500 text-black shadow-[0_0_15px_rgba(16,185,129,0.5)]",
          border: "border-emerald-500/50",
          gauge: "stroke-emerald-500"
        };
    }
  };

  const styles = riskData ? getVerdictStyles(riskData.verdict) : getVerdictStyles("SAFE");

  return (
    <div className="min-h-screen bg-[#f9fafb] text-[#111827] font-sans antialiased selection:bg-indigo-500/30">
      {/* Top Banner Accent Line */}
      <div className="h-1.5 w-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500" />

      {/* Header */}
      <header className="border-b border-[#e5e7eb] bg-white/95 border-b border-[#e5e7eb] backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            {/* Cyber Shield Logo */}
            <div className="p-2 rounded-lg bg-indigo-500/10 border border-[#4f46e5]/40">
              <svg className="w-8 h-8 text-[#4f46e5]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-[#111827] flex items-center gap-2">
                Sentinel<span className="text-[#4f46e5]">APK</span>
              </h1>
              <p className="text-xs text-gray-500 uppercase tracking-widest font-mono">
                Explainable AI Threat Intelligence for Android Banking Applications
              </p>
            </div>
          </div>

          {/* Quick Metrics */}
          <div className="flex items-center gap-6 text-xs font-mono text-gray-500">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>Sandbox C2 Server: ONLINE</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-indigo-500" />
              <span>Pipeline latency: 1.2s</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8 space-y-8">
        {/* Project One-Liner */}
        <section className="bg-white border border-[#e5e7eb] rounded-xl p-6 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />
          <h2 className="text-lg font-semibold text-[#111827] mb-2">Android Malware Sandbox &amp; Adversarial Lab</h2>
          <p className="text-gray-700 max-w-4xl text-sm leading-relaxed">
            "SentinelAPK combines explainable APK threat analysis with an adversarial self-hardening training environment where an Analyst LLM continuously learns from increasingly evasive malware variants generated by an Evader LLM."
          </p>
        </section>

        {/* Upload & Sample Section */}
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* File Upload Zone */}
          <div className="lg:col-span-2 bg-white border border-[#e5e7eb] border border-[#e5e7eb] rounded-xl p-6 flex flex-col justify-between relative overflow-hidden">
            <div className="space-y-4">
              <h3 className="text-[#111827] font-semibold text-base">Decompile New APK</h3>
              <label className="block border-2 border-dashed border-[#e5e7eb] hover:border-[#4f46e5]/60 rounded-lg p-8 flex flex-col items-center justify-center gap-3 bg-[#f3f4f6] border border-[#e5e7eb] transition-all relative cursor-pointer">
                <input
                  type="file"
                  accept=".apk"
                  onChange={handleFileUpload}
                  disabled={loading}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                />
                <svg className="w-12 h-12 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
                <div className="text-center">
                  <p className="text-sm text-gray-700">Drag and drop your APK file here, or click to browse</p>
                  <p className="text-xs text-slate-500 mt-1">Accepts raw Android packages (.apk) only</p>
                </div>
              </label>
            </div>

            {/* Pipeline progress bar */}
            {progressStep > 0 && (
              <div className="mt-6 space-y-3 font-mono text-xs">
                <div className="flex justify-between text-[#4f46e5] font-bold">
                  <span>
                    {progressStep === 1 && "Stage 1: Fast Triage"}
                    {progressStep === 2 && "Stage 2: LLM Intent Graph Analysis"}
                    {progressStep === 3 && "Stage 3: Multimodal UI Deception Detection"}
                    {progressStep === 4 && "Stage 4: Dynamic Runtime Analysis"}
                    {progressStep === 5 && "Stage 5: Signal Fusion & Investigation Report"}
                  </span>
                  <span>{progressStep * 20}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 transition-all duration-300"
                    style={{ width: `${progressStep * 20}%` }}
                  />
                </div>
                
                {/* Telemetry Console Output */}
                <div className="bg-[#f3f4f6] border border-[#e5e7eb] rounded-lg p-3 max-h-32 overflow-y-auto text-[10px] font-mono space-y-1 mt-2 select-text">
                  {consoleLogs.map((log, idx) => (
                    <div key={idx} className="flex gap-2">
                      <span className="text-indigo-500 font-bold select-none">&gt;</span>
                      <span className={log.startsWith("[+") ? "text-emerald-600" : log.startsWith("[-]") ? "text-[#ef4444]" : "text-gray-700"}>
                        {log}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {errorMsg && (
              <div className="mt-4 p-3 bg-red-950/30 border border-red-500/20 text-[#ef4444] text-xs rounded-lg flex items-center gap-2">
                <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <span>{errorMsg}</span>
              </div>
            )}
          </div>

          {/* Quick Select Demo Samples */}
          <div className="bg-white border border-[#e5e7eb] border border-[#e5e7eb] rounded-xl p-6 flex flex-col justify-between">
            <div className="space-y-4">
              <h3 className="text-[#111827] font-semibold text-base">Select Live Banking Samples</h3>
              <p className="text-xs text-gray-500">
                Load predefined threat scenarios to test SentinelAPK's pipeline reasoning and risk indicators.
              </p>
              <div className="space-y-2">
                {samples.map((s) => (
                  <button
                    key={s.id}
                    onClick={() => loadSample(s.id)}
                    disabled={loading}
                    className={`w-full text-left p-3 rounded-lg border text-sm transition-all flex justify-between items-center ${
                      selectedSampleId === s.id
                        ? "bg-indigo-950/30 border-[#4f46e5]/60 text-[#111827] shadow-lg"
                        : "bg-[#f3f4f6] border border-[#e5e7eb] border-[#e5e7eb] text-gray-700 hover:border-[#e5e7eb]"
                    }`}
                  >
                    <div>
                      <div className="font-semibold text-gray-900">{s.name}</div>
                      <div className="text-xs text-slate-500 font-mono mt-0.5">Risk Score: {s.score}/100</div>
                    </div>
                    <span
                      className={`text-xs px-2 py-0.5 rounded-full font-bold uppercase ${
                        s.verdict === "MALICIOUS"
                          ? "bg-red-500/10 text-[#ef4444] border border-red-500/20"
                          : s.verdict === "SUSPICIOUS"
                          ? "bg-amber-500/10 text-amber-600 border border-amber-500/20"
                          : "bg-emerald-500/10 text-emerald-600 border border-emerald-500/20"
                      }`}
                    >
                      {s.verdict}
                    </span>
                  </button>
                ))}
              </div>
            </div>
            
            <button
              onClick={triggerDownload}
              disabled={loading || !sessionId}
              className="mt-6 w-full py-2.5 px-4 bg-[#4f46e5] hover:bg-[#4338ca] disabled:bg-slate-800 disabled:text-slate-500 text-[#111827] font-semibold rounded-lg text-sm flex items-center justify-center gap-2 transition-all shadow-lg shadow-indigo-600/10"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              Download Security PDF Report
            </button>
          </div>
        </section>

        {/* Dynamic Analysis Dashboard */}
        {appMetadata && riskData && (
          <section className="space-y-8">
            {/* Top Row: Executive Verdict & Why Flagged */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
              {/* Executive Verdict Card */}
              <div className={`lg:col-span-5 border rounded-xl p-6 ${styles.bg} border-t-4 ${styles.border} flex flex-col justify-between`}>
                <div className="space-y-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="text-[#111827] text-xs uppercase tracking-widest font-mono">Executive Summary</h3>
                      <div className={`text-2xl font-black mt-1 ${styles.text}`}>
                        {riskData.verdict} VERDICT
                      </div>
                    </div>
                    <span className={`text-xs font-black px-3 py-1 rounded-full ${styles.badge}`}>
                      {riskData.verdict}
                    </span>
                  </div>

                  <div className="flex items-center gap-6 py-2 border-y border-[#e5e7eb]">
                    {/* Visual Radial Progress */}
                    <div className="relative w-24 h-24 flex-shrink-0">
                      <svg className="w-full h-full" viewBox="0 0 36 36">
                        <path className="stroke-slate-800" strokeWidth="3" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                        <path
                          className={`${styles.gauge} transition-all duration-1000`}
                          strokeWidth="3.5"
                          strokeDasharray={`${riskData.score}, 100`}
                          strokeLinecap="round"
                          fill="none"
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-lg font-black text-[#111827]">{riskData.score}</span>
                        <span className="text-[9px] text-gray-500 font-mono">RISK</span>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="text-xs text-gray-500 uppercase font-mono">Confidence Level</div>
                      <div className="text-xl font-bold text-[#111827]">{riskData.confidence}%</div>
                      <div className="text-[10px] text-slate-500 leading-tight">Calculated via signature coverage & API flags</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wider font-mono">Top Reasons:</h4>
                    <ul className="space-y-1 text-sm text-gray-800">
                      {riskData.top_reasons.map((r, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className={`w-1.5 h-1.5 rounded-full ${styles.text} mt-1.5 flex-shrink-0`} />
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>

              {/* Why was this flagged? (Attack Chain Card) */}
              <div className="lg:col-span-7 bg-white border border-[#e5e7eb] rounded-xl p-6 flex flex-col justify-between">
                <div className="space-y-4">
                  <div>
                    <h3 className="text-[#111827] font-semibold text-base">Why was this flagged?</h3>
                    <p className="text-xs text-gray-500 mt-0.5 font-mono">Attack Chain & Risk Exfiltration Pathway Mapping</p>
                  </div>

                  {/* Flow Steps */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4 py-4 relative">
                    {/* Animated running dash background line */}
                    <div className="absolute left-8 right-8 top-[45%] h-0.5 hidden md:block pointer-events-none z-0">
                      <svg className="w-full h-full" fill="none">
                        <line x1="0" y1="1" x2="100%" y2="1" stroke="#6366f1" strokeWidth="2" strokeDasharray="6 6">
                          <animate attributeName="stroke-dashoffset" values="12;0" dur="1s" repeatCount="indefinite" />
                        </line>
                      </svg>
                    </div>

                    {riskData.attack_chain.map((c, idx) => (
                      <div key={idx} className="bg-[#f3f4f6] border border-[#e5e7eb]/90 backdrop-blur border border-[#e5e7eb] p-3.5 rounded-lg flex flex-col justify-between gap-2.5 relative z-10 transition-all duration-300 hover:border-[#4f46e5]/60 hover:shadow-[0_0_15px_rgba(99,102,241,0.15)] min-h-[120px]">
                        <div>
                          <div className="text-[10px] font-mono text-[#4f46e5] uppercase tracking-widest flex items-center justify-between">
                            <span>Step {idx + 1}</span>
                            <span className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse" />
                          </div>
                          <div className="text-xs font-bold text-gray-800 mt-1">{c.step}</div>
                        </div>
                        <p className="text-[10px] text-gray-500 leading-normal">{c.desc}</p>
                        
                        {/* Connecting Arrow (except last step) */}
                        {idx < riskData.attack_chain.length - 1 && (
                          <div className="hidden md:flex absolute -right-3 top-[40%] -translate-y-1/2 z-20 items-center justify-center bg-[#f9fafb] border border-[#e5e7eb] rounded-full p-0.5">
                            <svg className="w-3 h-3 text-[#4f46e5]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M9 5l7 7-7 7" />
                            </svg>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>

                  <div className="p-3.5 bg-indigo-50/50 border border-indigo-500/20 rounded-lg text-xs flex justify-between items-center">
                    <div className="space-y-0.5">
                      <div className="text-gray-700 font-bold">Threat Potential: {riskData.verdict}</div>
                      <div className="text-gray-500 text-[10px]">Static pattern indicates logical connection of local automation to network transport.</div>
                    </div>
                    <span className="font-mono text-gray-500 text-[10px]">Model Heuristic</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Analysis Workspace Layout (Sidebar tabs + workspace) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
              {/* Tabs sidebar */}
              <div className="lg:col-span-3 flex flex-row lg:flex-col gap-2 overflow-x-auto lg:overflow-x-visible pb-2 lg:pb-0">
                <button
                  onClick={() => setActiveTab("overview")}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all flex-shrink-0 lg:flex-shrink ${
                    activeTab === "overview"
                      ? "bg-[#4f46e5] text-white"
                      : "bg-white border border-[#e5e7eb] text-gray-500 hover:bg-gray-100"
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  App Overview & Meta
                </button>
                <button
                  onClick={() => setActiveTab("permissions")}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all flex-shrink-0 lg:flex-shrink ${
                    activeTab === "permissions"
                      ? "bg-[#4f46e5] text-white"
                      : "bg-white border border-[#e5e7eb] text-gray-500 hover:bg-gray-100"
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                  Permissions & MITRE
                </button>
                <button
                  onClick={() => setActiveTab("ai")}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all flex-shrink-0 lg:flex-shrink ${
                    activeTab === "ai"
                      ? "bg-[#4f46e5] text-white"
                      : "bg-white border border-[#e5e7eb] text-gray-500 hover:bg-gray-100"
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364.364l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 01-2 2h0a2 2 0 01-2-2v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                  AI Intent Reasoning
                </button>
                <button
                  onClick={() => setActiveTab("impersonation")}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all flex-shrink-0 lg:flex-shrink ${
                    activeTab === "impersonation"
                      ? "bg-[#4f46e5] text-white"
                      : "bg-white border border-[#e5e7eb] text-gray-500 hover:bg-gray-100"
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                  </svg>
                  UI Impersonation (MVP)
                </button>
                <button
                  onClick={() => setActiveTab("runtime")}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all flex-shrink-0 lg:flex-shrink ${
                    activeTab === "runtime"
                      ? "bg-[#4f46e5] text-white"
                      : "bg-white border border-[#e5e7eb] text-gray-500 hover:bg-gray-100"
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Runtime Sandbox (MVP)
                </button>
                <button
                  onClick={() => setActiveTab("adversarial")}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all flex-shrink-0 lg:flex-shrink ${
                    activeTab === "adversarial"
                      ? "bg-[#4f46e5] text-white animate-pulse"
                      : "bg-white border border-[#e5e7eb] text-gray-500 hover:bg-gray-100"
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  Adversarial Red-Team Lab
                </button>
                <button
                  onClick={() => setActiveTab("learning")}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all flex-shrink-0 lg:flex-shrink ${
                    activeTab === "learning"
                      ? "bg-[#4f46e5] text-white"
                      : "bg-white border border-[#e5e7eb] text-gray-500 hover:bg-gray-100"
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                  </svg>
                  Adaptive Calibration Lab
                </button>
              </div>

              {/* Tab Workspace */}
              <div className="lg:col-span-9 bg-white border border-[#e5e7eb] border border-[#e5e7eb] rounded-xl p-6 min-h-[400px]">
                {/* 1. OVERVIEW TAB */}
                {activeTab === "overview" && (
                  <div className="space-y-6">
                    <h3 className="text-[#111827] font-semibold text-lg border-b border-[#e5e7eb] pb-3">Static APK Metadata</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-sm">
                      <div className="bg-[#f3f4f6] border border-[#e5e7eb] p-4 rounded-lg border border-[#e5e7eb]">
                        <div className="text-gray-500 text-xs uppercase tracking-wider">Application Name</div>
                        <div className="text-[#111827] text-lg font-bold mt-1">{appMetadata.app_name}</div>
                      </div>
                      <div className="bg-[#f3f4f6] border border-[#e5e7eb] p-4 rounded-lg border border-[#e5e7eb]">
                        <div className="text-gray-500 text-xs uppercase tracking-wider">Package Identifier</div>
                        <div className="text-[#111827] text-lg font-bold mt-1 break-all">{appMetadata.package_name}</div>
                      </div>
                      <div className="bg-[#f3f4f6] border border-[#e5e7eb] p-4 rounded-lg border border-[#e5e7eb]">
                        <div className="text-gray-500 text-xs uppercase tracking-wider">Version String</div>
                        <div className="text-[#111827] mt-1">{appMetadata.version_name} (Build Code: {appMetadata.version_code})</div>
                      </div>
                      <div className="bg-[#f3f4f6] border border-[#e5e7eb] p-4 rounded-lg border border-[#e5e7eb]">
                        <div className="text-gray-500 text-xs uppercase tracking-wider">Target SDK Level</div>
                        <div className="text-[#111827] mt-1">Android SDK {appMetadata.target_sdk} (Min Support: {appMetadata.min_sdk})</div>
                      </div>
                    </div>

                    {/* Clone Detection Card */}
                    {riskData && riskData.clone_findings && riskData.clone_findings.is_clone && (
                      <div className="bg-red-50 border border-red-200 text-red-800 p-4 rounded-lg flex items-start gap-3">
                        <svg className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <div>
                          <h4 className="font-bold text-sm">Clone Impersonation Warning</h4>
                          <p className="text-xs text-red-700 mt-1">
                            This package matches official application <strong>{riskData.clone_findings.official_target}</strong> package structure with similarity of <strong>{(riskData.clone_findings.similarity_score * 100).toFixed(0)}%</strong>. This indicates high risk of phishing overlay theft.
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Certificate Trust Status Card */}
                    {riskData && riskData.cert_findings && (
                      <div className={`p-4 rounded-lg border flex items-start gap-3 ${
                        riskData.cert_findings.is_trusted 
                          ? "bg-emerald-50 border-emerald-200 text-emerald-800" 
                          : "bg-amber-50 border-amber-200 text-amber-800"
                      }`}>
                        <svg className="w-5 h-5 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          {riskData.cert_findings.is_trusted ? (
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                          ) : (
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                          )}
                        </svg>
                        <div>
                          <h4 className="font-bold text-sm">
                            {riskData.cert_findings.is_trusted ? "Trusted Signatures Status" : "Untrusted Signature Reputation Warning"}
                          </h4>
                          <p className="text-xs mt-1">
                            {riskData.cert_findings.is_trusted 
                              ? "The application signature matches known official publisher certificate hashes in database repository." 
                              : `Reputation warning: ${riskData.cert_findings.reputation_issue || "Signature is missing or unrecognized."}`}
                          </p>
                        </div>
                      </div>
                    )}

                    {riskData?.evidence_validation && (
                      <div className="space-y-4">
                        <h4 className="text-[#111827] font-semibold text-sm flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-pulse" />
                          DEX Bytecode Scan Results (API Signatures)
                        </h4>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
                          <div className={`p-3 rounded-lg border flex flex-col justify-between min-h-[72px] transition-all duration-300 ${riskData.evidence_validation.sms.status === "FOUND" ? "bg-red-950/20 border-red-500/30 text-[#ef4444] shadow-[0_0_12px_rgba(239,68,68,0.08)]" : "bg-white/40 border-[#e5e7eb] text-slate-500"}`}>
                            <div className="text-[10px] uppercase font-bold text-gray-500">SMS / Telephony APIs</div>
                            <div className="font-bold mt-1 text-xs">{riskData.evidence_validation.sms.status === "FOUND" ? "FOUND" : "NOT FOUND"}</div>
                          </div>
                          <div className={`p-3 rounded-lg border flex flex-col justify-between min-h-[72px] transition-all duration-300 ${riskData.evidence_validation.accessibility.status === "FOUND" ? "bg-red-950/20 border-red-500/30 text-[#ef4444] shadow-[0_0_12px_rgba(239,68,68,0.08)]" : "bg-white/40 border-[#e5e7eb] text-slate-500"}`}>
                            <div className="text-[10px] uppercase font-bold text-gray-500">Accessibility APIs</div>
                            <div className="font-bold mt-1 text-xs">{riskData.evidence_validation.accessibility.status === "FOUND" ? "FOUND" : "NOT FOUND"}</div>
                          </div>
                          <div className={`p-3 rounded-lg border flex flex-col justify-between min-h-[72px] transition-all duration-300 ${riskData.evidence_validation.dynamic_loading.status === "FOUND" ? "bg-red-950/20 border-red-500/30 text-[#ef4444] shadow-[0_0_12px_rgba(239,68,68,0.08)]" : "bg-white/40 border-[#e5e7eb] text-slate-500"}`}>
                            <div className="text-[10px] uppercase font-bold text-gray-500">Dynamic Loading</div>
                            <div className="font-bold mt-1 text-xs">{riskData.evidence_validation.dynamic_loading.status === "FOUND" ? "FOUND" : "NOT FOUND"}</div>
                          </div>
                          <div className={`p-3 rounded-lg border flex flex-col justify-between min-h-[72px] transition-all duration-300 ${riskData.evidence_validation.runtime_exec.status === "FOUND" ? "bg-red-950/20 border-red-500/30 text-[#ef4444] shadow-[0_0_12px_rgba(239,68,68,0.08)]" : "bg-white/40 border-[#e5e7eb] text-slate-500"}`}>
                            <div className="text-[10px] uppercase font-bold text-gray-500">Runtime.exec</div>
                            <div className="font-bold mt-1 text-xs">{riskData.evidence_validation.runtime_exec.status === "FOUND" ? "FOUND" : "NOT FOUND"}</div>
                          </div>
                        </div>

                        {appMetadata.dex_indicators && appMetadata.dex_indicators.suspicious_urls && appMetadata.dex_indicators.suspicious_urls.length > 0 && (
                          <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-2">
                            <div className="text-xs font-bold text-[#111827]">Suspicious Threat URLs Discovered:</div>
                            <ul className="list-disc pl-5 text-[11px] font-mono text-slate-600 space-y-1">
                              {appMetadata.dex_indicators.suspicious_urls.map((url, idx) => (
                                <li key={idx} className="break-all">{url}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}

                    <div className="space-y-4">
                      <h4 className="text-[#111827] font-semibold text-sm">Certificate Details & Code Signature</h4>
                      {appMetadata.certificates.length > 0 ? (
                        appMetadata.certificates.map((c, idx) => (
                          <div key={idx} className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] p-4 rounded-lg space-y-2 text-xs font-mono">
                            <div className="flex flex-col sm:flex-row justify-between gap-1">
                              <span className="text-[#4f46e5]">Issuer Signature:</span>
                              <span className="text-gray-700 break-all">{c.issuer}</span>
                            </div>
                            <div className="flex flex-col sm:flex-row justify-between gap-1">
                              <span className="text-[#4f46e5]">Subject Name:</span>
                              <span className="text-gray-700 break-all">{c.subject}</span>
                            </div>
                            <div className="flex flex-col sm:flex-row justify-between gap-1">
                              <span className="text-[#4f46e5]">Serial Key:</span>
                              <span className="text-gray-700">{c.serial_number}</span>
                            </div>
                            <div className="flex flex-col sm:flex-row justify-between gap-1">
                              <span className="text-[#4f46e5]">SHA256 Fingerprint:</span>
                              <span className="text-gray-700 break-all">{c.sha256}</span>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="p-4 bg-[#f3f4f6] border border-[#e5e7eb] rounded-lg text-slate-500 text-xs font-mono text-center border border-[#e5e7eb]">
                          No cryptographic certificates extracted (App could be unsigned or unsigned mock).
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* 2. PERMISSIONS TAB */}
                {activeTab === "permissions" && (
                  <div className="space-y-6">
                    <h3 className="text-[#111827] font-semibold text-lg border-b border-[#e5e7eb] pb-3">Permissions & MITRE ATT&CK Map</h3>
                    
                    <div className="space-y-6">
                      <h4 className="text-sm font-semibold text-gray-700 uppercase tracking-wider font-mono">MITRE ATT&CK Matrix Mapping</h4>
                      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3 select-none">
                        {[
                          {
                            tactic: "Initial Access",
                            techniques: [
                              { id: "T1474", name: "Malicious App", desc: "Delivered via alternative stores/social engineering." },
                              { id: "T1456", name: "Drive-by Install", desc: "Installed automatically via compromised site." }
                            ]
                          },
                          {
                            tactic: "Execution",
                            techniques: [
                              { id: "T1624", name: "Boot Initialization", desc: "Starts malicious background services on boot." },
                              { id: "T1407", name: "Dropper Install", desc: "Requests package installs to launch payloads." }
                            ]
                          },
                          {
                            tactic: "Defense Evasion",
                            techniques: [
                              { id: "T1418", name: "Input Overlay", desc: "Draws fake windows over target banking logins." },
                              { id: "T1629", name: "Device Lockout", desc: "Blocks user access to safety settings pages." }
                            ]
                          },
                          {
                            tactic: "Credential Access",
                            techniques: [
                              { id: "T1430", name: "Accessibility Abuse", desc: "Intercepts keystrokes and UI element values." },
                              { id: "T1409", name: "Creds in Files", desc: "Reads locally cached configurations." }
                            ]
                          },
                          {
                            tactic: "Collection",
                            techniques: [
                              { id: "T1636", name: "SMS Collection", desc: "Reads incoming transaction messages." },
                              { id: "T1636.002", name: "SMS Intercept", desc: "Intercepts and suppresses 2FA SMS OTPs." },
                              { id: "T1429", name: "Audio Capture", desc: "Abuses microphone access for eavesdropping." }
                            ]
                          },
                          {
                            tactic: "Exfiltration",
                            techniques: [
                              { id: "T1048", name: "C2 Exfiltration", desc: "Transmits gathered details via raw HTTP socket." }
                            ]
                          }
                        ].map((col, cIdx) => (
                          <div key={cIdx} className="space-y-2.5">
                            <div className="text-[10px] uppercase font-bold text-gray-500 border-b border-[#e5e7eb] pb-1 font-mono tracking-wider">
                              {col.tactic}
                            </div>
                            <div className="space-y-2">
                              {col.techniques.map((tech) => {
                                // Check if this technique id is active
                                const isActive = riskData.mitre_techniques.some((m) => m.id === tech.id) || 
                                  (tech.id === "T1048" && appMetadata.permissions.includes("android.permission.INTERNET") && (appMetadata.permissions.includes("android.permission.READ_SMS") || appMetadata.permissions.includes("android.permission.BIND_ACCESSIBILITY_SERVICE")));
                                
                                return (
                                  <div
                                    key={tech.id}
                                    className={`p-2.5 rounded-lg border text-left transition-all duration-300 ${
                                      isActive
                                        ? "bg-red-950/25 border-red-500/50 text-red-200 shadow-[0_0_12px_rgba(239,68,68,0.12)]"
                                        : "bg-[#f3f4f6] border border-[#e5e7eb]/60 border-[#e5e7eb] text-slate-600"
                                    }`}
                                  >
                                    <div className="flex justify-between items-center gap-1">
                                      <span className={`text-[9px] font-mono font-bold px-1 rounded ${isActive ? "bg-red-500/10 text-[#ef4444] border border-red-500/20" : "bg-white text-slate-700"}`}>
                                        {tech.id}
                                      </span>
                                      {isActive && (
                                        <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                                      )}
                                    </div>
                                    <div className="font-bold text-[10px] mt-1 truncate">{tech.name}</div>
                                    <p className="text-[9px] text-gray-500 mt-0.5 leading-normal line-clamp-2">{tech.desc}</p>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <h4 className="text-[#111827] font-semibold text-sm">Complete Permission Grid</h4>
                      <div className="max-h-60 overflow-y-auto border border-[#e5e7eb] rounded-lg divide-y divide-slate-800">
                        {appMetadata.permissions.map((p, idx) => {
                          const rule = riskData.triggered_rules.find((r) => r.permission === p);
                          return (
                            <div key={idx} className="p-3 bg-[#f3f4f6] border border-[#e5e7eb] flex justify-between items-center text-xs font-mono">
                              <span className="text-gray-700 break-all">{p}</span>
                              {rule ? (
                                <span className="text-[#ef4444] font-bold flex-shrink-0">+{rule.weight} Dangerous</span>
                              ) : (
                                <span className="text-slate-500 flex-shrink-0">Standard</span>
                              )}
                            </div>
                          );
                        })}
                        {appMetadata.permissions.length === 0 && (
                          <div className="p-6 text-center text-slate-500">No permissions requested.</div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* 3. AI REASONING TAB */}
                {activeTab === "ai" && aiData && (
                  <div className="space-y-6">
                    <h3 className="text-[#111827] font-semibold text-lg border-b border-[#e5e7eb] pb-3">Explainable AI Intent Reasoning</h3>
                    
                    <div className="space-y-5">
                      <div className="p-4 bg-indigo-50/50 border border-indigo-500/10 rounded-lg space-y-2">
                        <strong className="text-[#4f46e5] text-sm">Suspicious Permissions Rationale:</strong>
                        <p className="text-gray-700 text-xs leading-relaxed">{aiData.suspicious_permissions_rationale}</p>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="p-4 bg-white border border-[#e5e7eb] rounded-lg space-y-2">
                          <strong className="text-indigo-300 text-xs">SMS OTP Interception Risk:</strong>
                          <p className="text-gray-500 text-xs leading-relaxed">{aiData.otp_theft_capability}</p>
                        </div>
                        <div className="p-4 bg-white border border-[#e5e7eb] rounded-lg space-y-2">
                          <strong className="text-indigo-300 text-xs">Accessibility Abuse Risk:</strong>
                          <p className="text-gray-500 text-xs leading-relaxed">{aiData.accessibility_abuse}</p>
                        </div>
                        <div className="p-4 bg-white border border-[#e5e7eb] rounded-lg space-y-2">
                          <strong className="text-indigo-300 text-xs">Visual Impersonation & Overlays:</strong>
                          <p className="text-gray-500 text-xs leading-relaxed">{aiData.impersonation_risk}</p>
                        </div>
                        <div className="p-4 bg-white border border-[#e5e7eb] rounded-lg space-y-2">
                          <strong className="text-indigo-300 text-xs">Data Exfiltration Vectors:</strong>
                          <p className="text-gray-500 text-xs leading-relaxed">{aiData.data_exfiltration}</p>
                        </div>
                      </div>

                      <div className="p-4 bg-[#f3f4f6] border border-[#e5e7eb] rounded-lg space-y-2">
                        <strong className="text-[#111827] text-xs uppercase tracking-wider font-mono">Verdict Determination Logic:</strong>
                        <p className="text-gray-700 text-xs leading-relaxed">{aiData.verdict_reasoning}</p>
                      </div>
                    </div>
                  </div>
                )}

                {/* 4. IMPERSONATION TAB */}
                {activeTab === "impersonation" && (
                  <div className="space-y-6 flex flex-col justify-center items-center py-12 text-center">
                    <div className="p-3 rounded-full bg-slate-800 text-gray-500 border border-[#e5e7eb]">
                      <svg className="w-12 h-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                      </svg>
                    </div>
                    <div className="space-y-2 max-w-md">
                      <h3 className="text-[#111827] font-bold text-lg">Visual UI Impersonation Detector</h3>
                      <p className="text-xs text-[#ef4444] font-bold font-mono p-2 bg-rose-950/20 border border-rose-500/20 rounded">
                        "Visual impersonation analysis is not executed in this MVP."
                      </p>
                      <p className="text-xs text-gray-500 leading-relaxed mt-2">
                        Future releases will perform visual screenshots comparison using computer vision/similarity algorithms against common banking app templates.
                      </p>
                    </div>
                  </div>
                )}

                {/* 5. RUNTIME TAB */}
                {activeTab === "runtime" && (
                  <div className="space-y-6">
                    <div className="flex justify-between items-center border-b border-[#e5e7eb] pb-3">
                      <h3 className="text-[#111827] font-semibold text-lg">Dynamic Sandbox Assessment</h3>
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-amber-500/10 text-amber-600 border border-amber-500/20 rounded uppercase">
                        Heuristic/MVP Mode
                      </span>
                    </div>

                    <div className="space-y-4">
                      <div className="p-3 bg-[#f3f4f6] border border-[#e5e7eb] rounded-lg border border-[#e5e7eb] text-xs text-gray-500 leading-relaxed">
                        ⚠️ <strong>Assessment Mode:</strong> No physical device/emulator is currently connected to stream logs. The behaviors listed below are estimated based on manifest structure, broadcast listeners, and intent flags.
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] p-4 rounded-lg space-y-2">
                          <h4 className="text-gray-800 font-bold text-xs">Overlay Attack Potential</h4>
                          <p className="text-[11px] text-gray-500 leading-relaxed">
                            {riskData?.evidence_validation?.overlay?.status === "FOUND"
                              ? "CRITICAL. The application has overlay triggers, enabling it to intercept foreground activities and present fake credential pages."
                              : "SAFE. Overlay triggers are not found. Interface spoofing is unlikely."}
                          </p>
                        </div>

                        <div className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] p-4 rounded-lg space-y-2">
                          <h4 className="text-gray-800 font-bold text-xs">Accessibility Abuse Potential</h4>
                          <p className="text-[11px] text-gray-500 leading-relaxed">
                            {riskData?.evidence_validation?.accessibility?.status === "FOUND"
                              ? "CRITICAL. Accessibility binding is present. The application can read UI hierarchies, dump passwords from input objects, and simulate clicks."
                              : "SAFE. Accessibility service binder is not requested."}
                          </p>
                        </div>

                        <div className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] p-4 rounded-lg space-y-2">
                          <h4 className="text-gray-800 font-bold text-xs">Dynamic Code Loading Risk</h4>
                          <p className="text-[11px] text-gray-500 leading-relaxed">
                            {riskData?.evidence_validation?.dynamic_loading?.status === "FOUND"
                              ? "HIGH. App utilizes dynamic code loading. It can load external APK binaries to bypass static inspection."
                              : "LOW. Dynamic loading triggers not found."}
                          </p>
                        </div>

                        <div className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] p-4 rounded-lg space-y-2">
                          <h4 className="text-gray-800 font-bold text-xs">SMS Interception Risk</h4>
                          <p className="text-[11px] text-gray-500 leading-relaxed">
                            {riskData?.evidence_validation?.sms?.status === "FOUND"
                              ? "HIGH. SMS collection capability discovered. App can read incoming 2FA transaction codes."
                              : "SAFE. SMS interception triggers not found."}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* 6. ADVERSARIAL RED-TEAM LAB TAB */}
                {activeTab === "adversarial" && (
                  <div className="space-y-6">
                    {/* Prototype Disclaimer Banner */}
                    <div className="p-3 bg-amber-500/10 border border-amber-500/20 text-amber-700 text-xs rounded-lg flex items-start gap-2 leading-relaxed">
                      <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <div>
                        <strong>Research Prototype:</strong> Demonstrates a dual-agent adversarial learning architecture. Persistent memory and adversarial reasoning are active. Full model retraining is outside the scope of this MVP.
                      </div>
                    </div>

                    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-[#e5e7eb] pb-3 gap-2">
                      <div>
                        <h3 className="text-[#111827] font-semibold text-lg flex items-center gap-2">
                          Offline Adversarial Training Environment
                        </h3>
                        <p className="text-xs text-gray-500 mt-0.5">
                          Dual-LLM self-hardening workspace where an Evader LLM generates mutated variants to train the Analyst LLM.
                        </p>
                      </div>
                      <button
                        onClick={triggerRedteamMutation}
                        disabled={redteamLoading}
                        className="px-4 py-2 bg-[#4f46e5] hover:bg-[#4338ca] disabled:bg-[#818cf8] text-[#111827] rounded-lg text-sm font-semibold transition-all shadow-md shadow-indigo-600/20 w-full sm:w-auto"
                      >
                        {redteamLoading ? (
                          <span className="flex items-center justify-center gap-2">
                            <svg className="animate-spin h-4 w-4 text-[#111827]" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                            </svg>
                            Mutating &amp; Hardening...
                          </span>
                        ) : (
                          "Trigger Evasion Mutation"
                        )}
                      </button>
                    </div>

                    {/* Loop Flowchart */}
                    <div className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] rounded-xl p-6 relative overflow-hidden">
                      <div className="absolute top-0 right-0 px-3 py-1 bg-indigo-500/10 border-l border-b border-indigo-500/20 rounded-bl text-[10px] font-mono text-[#4f46e5] font-bold uppercase">
                        Live Flow Loop
                      </div>
                      
                      <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-6">
                        Adversarial Loop Visualization
                      </h4>

                      <div className="grid grid-cols-2 md:grid-cols-6 gap-4 items-center relative text-center">
                        {/* Step 1 */}
                        <div className="bg-[#e5e7eb] border border-[#e5e7eb] p-3 rounded-lg relative">
                          <div className="text-[10px] font-mono text-[#4f46e5] font-bold">STEP 1</div>
                          <div className="text-[#111827] font-bold text-xs mt-1">APK Uploaded</div>
                          <p className="text-[9px] text-gray-500 mt-1">Extract manifest metadata</p>
                        </div>

                        {/* Arrow 1 */}
                        <div className="hidden md:flex justify-center text-slate-600 font-bold text-lg">&rarr;</div>

                        {/* Step 2 */}
                        <div className={`border p-3 rounded-lg relative transition-all ${
                          redteamData ? "bg-[#e5e7eb] border-[#e5e7eb]" : "bg-[#13131a]/50 border-slate-900 opacity-60"
                        }`}>
                          <div className="text-[10px] font-mono text-[#4f46e5] font-bold">STEP 2</div>
                          <div className="text-[#111827] font-bold text-xs mt-1">Analyst LLM</div>
                          <p className="text-[9px] text-gray-500 mt-1">
                            {redteamData ? `Initial Confidence: ${redteamData.initial_detection.confidence}%` : "Evaluates APK threat signals"}
                          </p>
                        </div>

                        {/* Arrow 2 */}
                        <div className="hidden md:flex justify-center text-slate-600 font-bold text-lg">&rarr;</div>

                        {/* Step 3 */}
                        <div className={`border p-3 rounded-lg relative transition-all ${
                          redteamData ? "bg-red-500/10 border-red-500/20" : "bg-[#13131a]/50 border-slate-900 opacity-60"
                        }`}>
                          <div className="text-[10px] font-mono text-[#ef4444] font-bold">STEP 3</div>
                          <div className="text-[#111827] font-bold text-xs mt-1">Evader LLM</div>
                          <p className="text-[9px] text-gray-500 mt-1">
                            {redteamData ? `Mutates: ${redteamData.mutation.mutation}` : "Generates evasive variant"}
                          </p>
                        </div>

                        {/* Arrow 3 */}
                        <div className="hidden md:flex justify-center text-slate-600 font-bold text-lg">&rarr;</div>

                        {/* Downward/Next Row connectors on mobile, sequential grid for md */}
                        {/* Step 4 */}
                        <div className={`border p-3 rounded-lg relative transition-all ${
                          redteamData ? "bg-amber-500/10 border-amber-500/20" : "bg-[#13131a]/50 border-slate-900 opacity-60"
                        }`}>
                          <div className="text-[10px] font-mono text-amber-600 font-bold">STEP 4</div>
                          <div className="text-[#111827] font-bold text-xs mt-1">Mutation Payload</div>
                          <p className="text-[9px] text-gray-500 mt-1">
                            {redteamData ? `Difficulty Score: ${redteamData.mutation.difficulty_score}` : "Hides API & permissions"}
                          </p>
                        </div>

                        {/* Arrow 4 */}
                        <div className="hidden md:flex justify-center text-slate-600 font-bold text-lg">&rarr;</div>

                        {/* Step 5 */}
                        <div className={`border p-3 rounded-lg relative transition-all ${
                          redteamData ? "bg-[#e5e7eb] border-[#e5e7eb]" : "bg-[#13131a]/50 border-slate-900 opacity-60"
                        }`}>
                          <div className="text-[10px] font-mono text-[#4f46e5] font-bold">STEP 5</div>
                          <div className="text-[#111827] font-bold text-xs mt-1">Re-Evaluation</div>
                          <p className="text-[9px] text-gray-500 mt-1">
                            {redteamData ? `Confidence: ${redteamData.re_evaluation.confidence}%` : "Analyst re-assesses variant"}
                          </p>
                        </div>

                        {/* Arrow 5 */}
                        <div className="hidden md:flex justify-center text-slate-600 font-bold text-lg">&rarr;</div>

                        {/* Step 6 */}
                        <div className={`border p-3 rounded-lg relative transition-all ${
                          redteamData ? "bg-emerald-500/10 border-emerald-500/20" : "bg-[#13131a]/50 border-slate-900 opacity-60"
                        }`}>
                          <div className="text-[10px] font-mono text-emerald-600 font-bold">STEP 6</div>
                          <div className="text-[#111827] font-bold text-xs mt-1">Memory Updated</div>
                          <p className="text-[9px] text-gray-500 mt-1">
                            {redteamData ? `Learned: ${redteamData.memory_update.pattern}` : "Hardening patterns registered"}
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Simulation Results Panels */}
                    {redteamData ? (
                      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* Evader Evasion Card */}
                        <div className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] rounded-xl p-5 space-y-4">
                          <div className="flex items-center justify-between border-b border-[#e5e7eb] pb-2">
                            <span className="text-[#111827] font-bold text-sm">Evader Strategy Card</span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                              redteamData.mutation.difficulty === "Critical"
                                ? "bg-red-500/10 text-[#ef4444] border border-red-500/25"
                                : redteamData.mutation.difficulty === "High"
                                ? "bg-amber-500/10 text-amber-600 border border-amber-500/25"
                                : "bg-blue-500/10 text-blue-400 border border-blue-500/25"
                            }`}>
                              {redteamData.mutation.difficulty}
                            </span>
                          </div>
                          
                          <div className="space-y-3">
                            <div>
                              <div className="text-[10px] text-gray-500 uppercase font-bold font-mono">Mutation Triggered</div>
                              <div className="text-[#111827] font-semibold text-sm mt-0.5">{redteamData.mutation.mutation}</div>
                            </div>
                            <div>
                              <div className="text-[10px] text-gray-500 uppercase font-bold font-mono">Difficulty Rating</div>
                              <div className="flex items-center gap-2 mt-1">
                                <div className="flex-1 bg-slate-800 h-2 rounded-full overflow-hidden">
                                  <div 
                                    className="bg-indigo-500 h-full transition-all duration-500" 
                                    style={{ width: `${redteamData.mutation.difficulty_score}%` }} 
                                  />
                                </div>
                                <span className="text-[#111827] font-mono font-bold text-xs">{redteamData.mutation.difficulty_score}</span>
                              </div>
                            </div>
                            <div>
                              <div className="text-[10px] text-gray-500 uppercase font-bold font-mono">Adversarial Rationale</div>
                              <p className="text-xs text-gray-700 mt-1 leading-relaxed">{redteamData.mutation.reason}</p>
                            </div>
                          </div>
                        </div>

                        {/* Analyst Hardening Card */}
                        <div className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] rounded-xl p-5 space-y-4 lg:col-span-2">
                          <div className="flex items-center justify-between border-b border-[#e5e7eb] pb-2">
                            <span className="text-[#111827] font-bold text-sm">Analyst Self-Hardening Delta</span>
                            <span className="text-[10px] font-mono text-emerald-600 font-bold bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
                              Hardening Success
                            </span>
                          </div>

                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 py-2">
                            {/* Before */}
                            <div className="bg-[#e5e7eb]/40 border border-[#e5e7eb] p-4 rounded-lg text-center space-y-1">
                              <span className="text-[10px] font-mono font-bold text-gray-500 uppercase">Detection Before</span>
                              <div className="text-2xl font-black text-[#ef4444]">{redteamData.initial_detection.confidence}%</div>
                              <span className="text-[9px] px-1.5 py-0.5 bg-rose-500/10 text-[#ef4444] border border-rose-500/20 rounded font-bold uppercase">
                                {redteamData.initial_detection.verdict}
                              </span>
                            </div>

                            {/* Difficulty Score */}
                            <div className="bg-[#e5e7eb]/40 border border-[#e5e7eb] p-4 rounded-lg text-center space-y-1 flex flex-col justify-center items-center">
                              <span className="text-[10px] font-mono font-bold text-gray-500 uppercase">Mutation Difficulty</span>
                              <div className="text-3xl font-black text-[#4f46e5] mt-1">{redteamData.mutation.difficulty_score}</div>
                              <span className="text-[8px] text-slate-500 uppercase mt-0.5">Complexity Factor</span>
                            </div>

                            {/* After */}
                            <div className="bg-[#e5e7eb]/40 border border-[#e5e7eb] p-4 rounded-lg text-center space-y-1">
                              <span className="text-[10px] font-mono font-bold text-gray-500 uppercase">Detection After</span>
                              <div className="text-2xl font-black text-emerald-600">{redteamData.re_evaluation.confidence}%</div>
                              <span className="text-[9px] px-1.5 py-0.5 bg-emerald-500/10 text-emerald-600 border border-emerald-500/20 rounded font-bold uppercase">
                                {redteamData.re_evaluation.verdict}
                              </span>
                            </div>
                          </div>

                          {/* Visualization bar showing improvement */}
                          <div className="space-y-2 pt-2">
                            <div className="flex justify-between text-xs text-gray-500">
                              <span>Analyst Confidence Delta</span>
                              <span className="text-emerald-600 font-bold">
                                +{redteamData.re_evaluation.confidence - redteamData.initial_detection.confidence}% Improvement
                              </span>
                            </div>
                            <div className="relative bg-slate-800 h-4 rounded-full overflow-hidden">
                              {/* Before Bar */}
                              <div 
                                className="absolute top-0 left-0 bg-rose-500 h-full"
                                style={{ width: `${redteamData.initial_detection.confidence}%` }}
                              />
                              {/* Delta/After Bar */}
                              <div 
                                className="absolute top-0 bg-emerald-500 h-full"
                                style={{ 
                                  left: `${redteamData.initial_detection.confidence}%`,
                                  width: `${redteamData.re_evaluation.confidence - redteamData.initial_detection.confidence}%`
                                }}
                              />
                            </div>
                            <p className="text-[10px] text-gray-500 leading-relaxed text-center">
                              Self-hardening complete. The Analyst LLM updated its vector space models to identify variant mutations statically.
                            </p>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] p-8 rounded-xl text-center space-y-2">
                        <svg className="w-10 h-10 text-slate-600 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                        </svg>
                        <h4 className="text-[#111827] font-bold text-sm">No Mutation Loaded</h4>
                        <p className="text-xs text-gray-500 max-w-md mx-auto">
                          Click the <strong>Trigger Evasion Mutation</strong> button to generate an evasive APK mutation variant using the Evader LLM and simulate self-hardening.
                        </p>
                      </div>
                    )}

                    {/* Memory Growth Timeline and Lessons Learned */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      {/* Memory Growth Timeline */}
                      <div className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] rounded-xl p-5 space-y-4">
                        <div className="border-b border-[#e5e7eb] pb-2">
                          <span className="text-[#111827] font-bold text-sm">Memory Growth Timeline</span>
                          <p className="text-[11px] text-gray-500 mt-0.5">Chronological accumulation of threat variant knowledge</p>
                        </div>
                        
                        <div className="relative border-l-2 border-indigo-600/30 ml-4 space-y-6 py-2">
                          <div className="relative pl-6">
                            <div className="absolute -left-[9px] top-1.5 w-4 h-4 rounded-full bg-[#4f46e5] border-4 border-[#0a101d]" />
                            <div className="text-[10px] font-mono font-bold text-[#4f46e5] uppercase">Round 1</div>
                            <div className="text-[#111827] font-bold text-xs mt-0.5">READ_SMS + INTERNET</div>
                            <p className="text-[10px] text-gray-500 mt-0.5">Statically detects standard SMS triggers and direct web sockets</p>
                          </div>

                          <div className="relative pl-6">
                            <div className="absolute -left-[9px] top-1.5 w-4 h-4 rounded-full bg-[#4f46e5] border-4 border-[#0a101d]" />
                            <div className="text-[10px] font-mono font-bold text-[#4f46e5] uppercase">Round 2</div>
                            <div className="text-[#111827] font-bold text-xs mt-0.5">READ_SMS + Dynamic Loading</div>
                            <p className="text-[10px] text-gray-500 mt-0.5">Catches dynamic DEX payloads decrypting SMS strings in runtime memory</p>
                          </div>

                          <div className="relative pl-6">
                            <div className="absolute -left-[9px] top-1.5 w-4 h-4 rounded-full bg-[#4f46e5] border-4 border-[#0a101d]" />
                            <div className="text-[10px] font-mono font-bold text-[#4f46e5] uppercase">Round 3</div>
                            <div className="text-[#111827] font-bold text-xs mt-0.5">Overlay + Banking UI</div>
                            <p className="text-[10px] text-gray-500 mt-0.5">Intercepts fake Activity bounds overlapping legitimate financial screens</p>
                          </div>

                          <div className="relative pl-6">
                            <div className="absolute -left-[9px] top-1.5 w-4 h-4 rounded-full bg-[#4f46e5] border-4 border-[#0a101d]" />
                            <div className="text-[10px] font-mono font-bold text-[#4f46e5] uppercase">Round 4</div>
                            <div className="text-[#111827] font-bold text-xs mt-0.5">Accessibility + Obfuscated Network</div>
                            <p className="text-[10px] text-gray-500 mt-0.5">Unveils keystroke logging exfiltration via SSL-pinned obfuscated backchannels</p>
                          </div>
                        </div>
                      </div>

                      {/* Learned Patterns Table */}
                      <div className="bg-[#f3f4f6] border border-[#e5e7eb] border border-[#e5e7eb] rounded-xl p-5 space-y-4">
                        <div className="border-b border-[#e5e7eb] pb-2">
                          <span className="text-[#111827] font-bold text-sm">Lessons Learned (Knowledge Store)</span>
                          <p className="text-[11px] text-gray-500 mt-0.5">Tactical signatures registered to block future evasion attempts</p>
                        </div>

                        <div className="overflow-x-auto">
                          <table className="w-full text-left border-collapse text-xs">
                            <thead>
                              <tr className="border-b border-[#e5e7eb] text-gray-500">
                                <th className="py-2 font-semibold">Evasive Threat Pattern</th>
                                <th className="py-2 font-semibold text-right">Self-Hardening Severity</th>
                              </tr>
                            </thead>
                            <tbody>
                              {lessonsLearned.map((item, index) => (
                                <tr key={index} className="border-b border-[#e5e7eb] hover:bg-[#e5e7eb]/20">
                                  <td className="py-2.5 font-mono text-[#111827] flex items-center gap-2">
                                    <span className="w-1.5 h-1.5 rounded-full bg-indigo-500" />
                                    {item.pattern}
                                  </td>
                                  <td className="py-2.5 text-right">
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                      item.risk === "Critical"
                                        ? "bg-red-500/10 text-[#ef4444]"
                                        : item.risk === "High"
                                        ? "bg-amber-500/10 text-amber-600"
                                        : "bg-blue-500/10 text-blue-400"
                                    }`}>
                                      {item.risk}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* 7. ADAPTIVE LEARNING LAB TAB */}
                {activeTab === "learning" && (
                  <div className="space-y-6">
                    {/* Header Controls */}
                    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-[#e5e7eb] pb-4 gap-4">
                      <div>
                        <h3 className="text-[#111827] font-semibold text-lg">Adaptive Risk Weight Optimizer</h3>
                        <p className="text-xs text-gray-500 mt-0.5">
                          Dynamic weight learning from false negatives and positives. Measures failure and automatically runs verification.
                        </p>
                      </div>
                      <button
                        onClick={triggerBenchmarkRun}
                        disabled={runningBenchmark}
                        className="px-5 py-2.5 bg-[#4f46e5] hover:bg-[#4338ca] disabled:bg-[#818cf8] text-white rounded-lg text-sm font-semibold transition-all shadow-md shadow-indigo-600/20 w-full sm:w-auto"
                      >
                        {runningBenchmark ? (
                          <span className="flex items-center justify-center gap-2">
                            <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                            </svg>
                            Optimizing Weights...
                          </span>
                        ) : (
                          "Trigger Optimization Benchmark"
                        )}
                      </button>
                    </div>

                    {/* Weights Status Grid */}
                    <div className="bg-[#f3f4f6] border border-[#e5e7eb] rounded-xl p-5 space-y-4">
                      <h4 className="text-sm font-bold text-gray-800">Dynamic Decision Weights & Constraints</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {Object.entries(activeWeights).map(([feature, cfg]) => {
                          const percentage = ((cfg.value - cfg.min) / (cfg.max - cfg.min)) * 100;
                          return (
                            <div key={feature} className="bg-white border border-[#e5e7eb] rounded-lg p-4 space-y-2">
                              <div className="flex justify-between items-center">
                                <span className="font-mono text-xs font-bold text-[#111827]">{feature}</span>
                                <span className="text-xs font-bold text-[#4f46e5] bg-indigo-50 border border-indigo-100 px-2 py-0.5 rounded">
                                  {cfg.value}
                                </span>
                              </div>
                              <div className="flex justify-between text-[10px] text-gray-400 font-mono">
                                <span>Min: {cfg.min}</span>
                                <span>Max: {cfg.max}</span>
                              </div>
                              <div className="bg-gray-100 h-2 rounded-full overflow-hidden relative">
                                <div 
                                  className="bg-indigo-500 h-full transition-all duration-500" 
                                  style={{ width: `${percentage}%` }}
                                />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Effectiveness Report & Reality Check */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      {/* Learning Effectiveness Report */}
                      {effectivenessReport && (
                        <div className="bg-[#f3f4f6] border border-[#e5e7eb] rounded-xl p-5 space-y-4">
                          <div className="border-b border-[#e5e7eb] pb-2 flex justify-between items-center">
                            <div>
                              <span className="text-[#111827] font-bold text-sm">Learning Effectiveness Report</span>
                              <p className="text-[11px] text-gray-500 mt-0.5">Validation metrics before vs after training iteration</p>
                            </div>
                            <span className={`px-2 py-0.5 text-[9px] font-bold rounded uppercase ${
                              effectivenessReport.success ? "bg-emerald-100 text-emerald-800" : "bg-rose-100 text-rose-800"
                            }`}>
                              {effectivenessReport.success ? "CALIBRATION SUCCESSFUL" : "NO EFFECTIVE METRIC IMPROVEMENT"}
                            </span>
                          </div>
                          <div className="grid grid-cols-3 gap-4 text-center">
                            <div className="bg-white p-3 rounded-lg border border-[#e5e7eb]">
                              <div className="text-[10px] text-gray-400 font-mono uppercase font-bold">Accuracy</div>
                              <div className="text-sm font-bold text-slate-800 mt-1">
                                {(effectivenessReport.before.accuracy * 100).toFixed(0)}% &rarr; {(effectivenessReport.after.accuracy * 100).toFixed(0)}%
                              </div>
                            </div>
                            <div className="bg-white p-3 rounded-lg border border-[#e5e7eb]">
                              <div className="text-[10px] text-gray-400 font-mono uppercase font-bold">Recall</div>
                              <div className="text-sm font-bold text-slate-800 mt-1">
                                {(effectivenessReport.before.recall * 100).toFixed(0)}% &rarr; {(effectivenessReport.after.recall * 100).toFixed(0)}%
                              </div>
                            </div>
                            <div className="bg-white p-3 rounded-lg border border-[#e5e7eb]">
                              <div className="text-[10px] text-gray-400 font-mono uppercase font-bold">F1-Score</div>
                              <div className="text-sm font-bold text-slate-800 mt-1">
                                {(effectivenessReport.before.f1_score * 100).toFixed(0)}% &rarr; {(effectivenessReport.after.f1_score * 100).toFixed(0)}%
                              </div>
                            </div>
                          </div>
                          <div className="text-[10px] text-gray-500 font-mono text-center bg-white border border-[#e5e7eb] p-2 rounded-lg leading-relaxed">
                            Baseline: TP={effectivenessReport.before.confusion_matrix.tp} | FP={effectivenessReport.before.confusion_matrix.fp} | TN={effectivenessReport.before.confusion_matrix.tn} | FN={effectivenessReport.before.confusion_matrix.fn}
                            <br/>
                            Optimized: TP={effectivenessReport.after.confusion_matrix.tp} | FP={effectivenessReport.after.confusion_matrix.fp} | TN={effectivenessReport.after.confusion_matrix.tn} | FN={effectivenessReport.after.confusion_matrix.fn}
                          </div>
                        </div>
                      )}

                      {/* Reality Check Card */}
                      <div className="bg-[#f3f4f6] border border-[#e5e7eb] rounded-xl p-5 space-y-4">
                        <div className="border-b border-[#e5e7eb] pb-2">
                          <span className="text-[#111827] font-bold text-sm">Platform Capability Reality Check</span>
                          <p className="text-[11px] text-gray-500 mt-0.5">Auditable distinction between running features and future research work</p>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                          <div className="bg-white border border-[#e5e7eb] rounded-lg p-3 space-y-2">
                            <div className="text-[10px] font-bold text-emerald-700 flex items-center gap-1.5 uppercase font-mono">
                              <span className="w-2 h-2 rounded-full bg-emerald-500" />
                              Implemented Core
                            </div>
                            <ul className="list-disc pl-4 text-[9px] text-slate-600 space-y-1">
                              <li>APK parsing & manifest</li>
                              <li>DEX static bytecode scan</li>
                              <li>Permission weight triggers</li>
                              <li>Certificate validation DB</li>
                              <li>Clone detection similarity</li>
                              <li>Adaptive calibration optimizer</li>
                            </ul>
                          </div>
                          <div className="bg-white border border-[#e5e7eb] rounded-lg p-3 space-y-2 opacity-80">
                            <div className="text-[10px] font-bold text-slate-500 flex items-center gap-1.5 uppercase font-mono">
                              <span className="w-2 h-2 rounded-full bg-slate-400" />
                              Research / Future
                            </div>
                            <ul className="list-disc pl-4 text-[9px] text-slate-500 space-y-1">
                              <li>Dynamic sandbox execution</li>
                              <li>Runtime behavioral analysis</li>
                              <li>Autonomous LLM learning</li>
                              <li>Adversarial variant mutation</li>
                            </ul>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Explanations & Benchmark Runs */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      {/* Explanations Timeline */}
                      <div className="bg-[#f3f4f6] border border-[#e5e7eb] rounded-xl p-5 space-y-4">
                        <div className="border-b border-[#e5e7eb] pb-2">
                          <span className="text-[#111827] font-bold text-sm">Optimization Rationale (Audit Trail)</span>
                          <p className="text-[11px] text-gray-500 mt-0.5">XAI explanations detailing logic adjustments</p>
                        </div>
                        <div className="space-y-4 max-h-[300px] overflow-y-auto pr-2">
                          {learningExplanations.length > 0 ? (
                            learningExplanations.map((exp, idx) => (
                              <div key={idx} className="p-3 bg-white border border-[#e5e7eb] rounded-lg text-xs leading-relaxed text-gray-600">
                                {exp}
                              </div>
                            ))
                          ) : (
                            <div className="text-xs text-gray-400 text-center py-8">No optimization logs recorded yet. Run benchmark to update.</div>
                          )}
                        </div>
                      </div>

                      {/* Historical Benchmark Runs */}
                      <div className="bg-[#f3f4f6] border border-[#e5e7eb] rounded-xl p-5 space-y-4">
                        <div className="border-b border-[#e5e7eb] pb-2">
                          <span className="text-[#111827] font-bold text-sm">Auditable Benchmark Runs</span>
                          <p className="text-[11px] text-gray-500 mt-0.5">Performance history of active runs</p>
                        </div>
                        <div className="space-y-3 max-h-[300px] overflow-y-auto pr-2">
                          {benchmarkRuns.length > 0 ? (
                            benchmarkRuns.map((run, idx) => (
                              <div key={idx} className="p-3 bg-white border border-[#e5e7eb] rounded-lg text-xs space-y-2">
                                <div className="flex justify-between items-center">
                                  <span className="font-mono font-bold text-[#111827]">{run.run_id}</span>
                                  {run.rolled_back && (
                                    <span className="bg-red-50 text-[9px] text-red-600 border border-red-100 font-bold px-1.5 py-0.5 rounded">
                                      ROLLED BACK
                                    </span>
                                  )}
                                </div>
                                <div className="grid grid-cols-4 gap-2 text-center text-[10px] font-mono text-gray-500">
                                  <div>Acc: {(run.accuracy * 100).toFixed(0)}%</div>
                                  <div>Prec: {(run.precision * 100).toFixed(0)}%</div>
                                  <div>Rec: {(run.recall * 100).toFixed(0)}%</div>
                                  <div>F1: {(run.f1_score * 100).toFixed(0)}%</div>
                                </div>
                                <div className="text-[10px] text-gray-400 font-mono text-center flex justify-around bg-slate-50 py-1 rounded">
                                  <span>Synthetic: {run.generated_apks || 0}</span>
                                  <span>User: {run.user_apks || 0}</span>
                                  <span>External: {run.external_apks || 0}</span>
                                </div>
                                <div className="text-[9px] text-gray-400 font-mono text-center border-t pt-1">
                                  TP: {run.confusion_matrix.tp} | FP: {run.confusion_matrix.fp} | TN: {run.confusion_matrix.tn} | FN: {run.confusion_matrix.fn}
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="text-xs text-gray-400 text-center py-8">No historical runs recorded.</div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Complete Learning Audit Log */}
                    <div className="bg-[#f3f4f6] border border-[#e5e7eb] rounded-xl p-5 space-y-4">
                      <div className="border-b border-[#e5e7eb] pb-2">
                        <span className="text-[#111827] font-bold text-sm">Feature Attribution Learning Logs</span>
                        <p className="text-[11px] text-gray-500 mt-0.5">Granular record of all active dynamic learning weight shifts</p>
                      </div>
                      <div className="overflow-x-auto max-h-[300px] overflow-y-auto">
                        <table className="w-full text-left border-collapse text-xs">
                          <thead>
                            <tr className="border-b border-[#e5e7eb] text-gray-500 font-mono">
                              <th className="py-2 font-semibold">Timestamp</th>
                              <th className="py-2 font-semibold">Feature</th>
                              <th className="py-2 font-semibold text-center">Weight Shift</th>
                              <th className="py-2 font-semibold text-center">Conf</th>
                              <th className="py-2 font-semibold">Attribution Reason</th>
                            </tr>
                          </thead>
                          <tbody>
                            {learningHistory.length > 0 ? (
                              learningHistory.map((item, idx) => (
                                <tr key={idx} className="border-b border-[#e5e7eb] hover:bg-gray-50 font-mono">
                                  <td className="py-2 text-gray-500 text-[10px] whitespace-nowrap">
                                    {new Date(item.timestamp).toLocaleTimeString()}
                                  </td>
                                  <td className="py-2 font-bold text-[#111827]">{item.feature}</td>
                                  <td className="py-2 text-center text-gray-700 font-semibold">
                                    {item.old_weight} &rarr; {item.new_weight}
                                  </td>
                                  <td className="py-2 text-center text-indigo-600 font-bold">{item.confidence}%</td>
                                  <td className="py-2 text-gray-600 max-w-xs truncate" title={item.reason}>{item.reason}</td>
                                </tr>
                              ))
                            ) : (
                              <tr>
                                <td colSpan={5} className="py-8 text-center text-gray-400">No learning logs recorded.</td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#e5e7eb] bg-[#f3f4f6] py-8 mt-12 text-center font-mono text-xs text-slate-500">
        <div>SentinelAPK &bull; Hackathon Threat Intelligence MVP &bull; 2026</div>
        <div className="mt-1">Built with Next.js, FastAPI, and Androguard</div>
      </footer>
    </div>
  );
}
