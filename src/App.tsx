import { useState, useEffect } from 'react';
import {
  Shield, Brain, Eye, Zap, Lock, CheckCircle, AlertTriangle,
  Activity, Users, Award, ArrowRight, Menu, X, Skull, Bug, Wifi,
  Database, Server, Terminal,
} from 'lucide-react';

// Define severity type
type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

// Define Threat type
interface Threat {
  type: string;
  severity: SeverityLevel;
  status: string;
  icon: JSX.Element;
  color: string;
}

function App() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [currentThreat, setCurrentThreat] = useState(0);
  const [detectionCount, setDetectionCount] = useState(1247);
  const [activeThreats, setActiveThreats] = useState(47);
  const [isScanning] = useState(true);
  const [urlInput, setUrlInput] = useState("");
  const [fileInput, setFileInput] = useState<File | null>(null);
  const [imageInput, setImageInput] = useState<File | null>(null);
  const [, setScanResult] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<any | null>(null);

  // Async scan handlers
const handleUrlScan = async () => {
  if (!urlInput) return alert("Please enter a URL");
  setScanResult("🔍 Scanning URL...");
  try {
    const response = await fetch('/api/scan/url', {
      method: 'POST',
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlInput }),
    });
    if (!response.ok) throw new Error("Scan failed");
    const result = await response.json();

    const stats = result.last_analysis_stats ?? result.data?.attributes?.last_analysis_stats ?? {};
    const analysisResults = result.analysisResults || {};

    let maliciousCount = 0;
    let totalCount = 0;

    if (Object.keys(stats).length > 0) {
      maliciousCount = stats.malicious ?? 0;
      totalCount = (Object.values(stats) as number[]).reduce((a, b) => a + b, 0);
    } else if (Object.keys(analysisResults).length > 0) {
      totalCount = Object.keys(analysisResults).length;
      maliciousCount = Object.values(analysisResults).filter((res: any) => res.category === 'malicious').length;
    }

    setScanResults({
      type: "URL",
      target: urlInput,
      detections: `${maliciousCount}/${totalCount}`,
      status: maliciousCount > 0 ? "Malicious" : "Clean",
      date: new Date().toLocaleString(),
      analysisResults: analysisResults,
    });
  } catch (error) {
    setScanResult("❌ Scan failed. Try again.");
  }
  setUrlInput("");
};

const handleFileScan = async () => {
  if (!fileInput) return alert("Please select a PDF file");
  setScanResult("📄 Scanning file...");
  try {
    const formData = new FormData();
    formData.append('file', fileInput);
    const response = await fetch('/api/scan/file', {
      method: 'POST',
      body: formData,
    });
    if (!response.ok) throw new Error("File scan failed");
    const result = await response.json();

    const stats = result.last_analysis_stats ?? result.data?.attributes?.last_analysis_stats ?? {};
    const analysisResults = result.analysisResults || {};

    let maliciousCount = 0;
    let totalCount = 0;

    if (Object.keys(stats).length > 0) {
      maliciousCount = stats.malicious ?? 0;
      totalCount = (Object.values(stats) as number[]).reduce((a, b) => a + b, 0);
    } else if (Object.keys(analysisResults).length > 0) {
      totalCount = Object.keys(analysisResults).length;
      maliciousCount = Object.values(analysisResults).filter((res: any) => res.category === 'malicious').length;
    }

    setScanResults({
      type: "File",
      target: fileInput.name,
      detections: `${maliciousCount}/${totalCount}`,
      status: maliciousCount > 0 ? "Malicious" : "Clean",
      date: new Date().toLocaleString(),
      analysisResults: analysisResults,
    });
  } catch (error) {
    setScanResult("❌ File scan failed.");
  }
  setFileInput(null);
};

const handleImageScan = async () => {
  if (!imageInput) return alert("Please select an image");
  setScanResult("🖼️ Scanning image...");
  try {
    const formData = new FormData();
    formData.append('image', imageInput);
    const response = await fetch('/api/scan/image', {
      method: 'POST',
      body: formData,
    });
    if (!response.ok) throw new Error("Image scan failed");
    const result = await response.json();

    const stats = result.last_analysis_stats ?? result.data?.attributes?.last_analysis_stats ?? {};
    const analysisResults = result.analysisResults || {};

    let maliciousCount = 0;
    let totalCount = 0;

    if (Object.keys(stats).length > 0) {
      maliciousCount = stats.malicious ?? 0;
      totalCount = (Object.values(stats) as number[]).reduce((a, b) => a + b, 0);
    } else if (Object.keys(analysisResults).length > 0) {
      totalCount = Object.keys(analysisResults).length;
      maliciousCount = Object.values(analysisResults).filter((res: any) => res.category === 'malicious').length;
    }

    setScanResults({
      type: "Image",
      target: imageInput.name,
      detections: `${maliciousCount}/${totalCount}`,
      status: maliciousCount > 0 ? "Malicious" : "Clean",
      date: new Date().toLocaleString(),
      analysisResults: analysisResults,
    });
  } catch (error) {
    setScanResult("❌ Image scan failed.");
  }
  setImageInput(null);
};



  // Input change handlers
  const onFileInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setFileInput(event.target.files ? event.target.files[0] : null);
  };

  const onImageInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setImageInput(event.target.files ? event.target.files[0] : null);
  };

  const threats: Threat[] = [
    {type: "Ransomware", severity: "CRITICAL", status: "NEUTRALIZED", icon: <Skull className="w-5 h-5" />, color: "red"},
    {type: "Zero-Day Exploit", severity: "CRITICAL", status: "BLOCKED", icon: <Bug className="w-5 h-5" />, color: "red"},
    {type: "Phishing Attack", severity: "HIGH", status: "CONTAINED", icon: <Wifi className="w-5 h-5" />, color: "orange"},
    {type: "SQL Injection", severity: "HIGH", status: "BLOCKED", icon: <Database className="w-5 h-5" />, color: "orange"},
    {type: "DDoS Attack", severity: "MEDIUM", status: "MITIGATED", icon: <Server className="w-5 h-5" />, color: "yellow"},
    {type: "Malware Injection", severity: "HIGH", status: "QUARANTINED", icon: <Terminal className="w-5 h-5" />, color: "orange"}
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentThreat(prev => (prev + 1) % threats.length);
      setDetectionCount(prev => prev + Math.floor(Math.random() * 5) + 1);
      setActiveThreats(prev => Math.max(1, prev + Math.floor(Math.random() * 3) - 1));
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const features = [
    {
      title: "AI-Powered Threat Detection",
      description: "Real-time analysis of network traffic using advanced machine learning algorithms to detect and prevent evolving threats.",
      icon: <Brain className="w-6 h-6" />,
      color: "from-red-500 to-pink-500"
    },
    {
      title: "End-to-End Encryption",
      description: "Military-grade encryption protocols ensuring absolute data privacy and secure communication across all channels.",
      icon: <Lock className="w-6 h-6" />,
      color: "from-blue-500 to-cyan-500"
    },
    {
      title: "Real-Time Intrusion Detection",
      description: "Detects unauthorized access attempts instantly and neutralizes them before damage can occur.",
      icon: <Shield className="w-6 h-6" />,
      color: "from-green-500 to-emerald-500"
    },
    {
      title: "Adaptive AI Defense",
      description: "Continuously evolves and learns from new threats, ensuring defense mechanisms stay one step ahead.",
      icon: <Activity className="w-6 h-6" />,
      color: "from-yellow-500 to-orange-500"
    },
    {
      title: "Threat Intelligence Network",
      description: "Shares and aggregates live threat data from global sources to enhance collective defense.",
      icon: <Users className="w-6 h-6" />,
      color: "from-purple-500 to-indigo-500"
    },
    {
      title: "Predictive Analytics",
      description: "Anticipates future attacks based on historical data patterns and AI forecasting models.",
      icon: <Eye className="w-6 h-6" />,
      color: "from-pink-500 to-fuchsia-500"
    },
    {
      title: "Automated Response",
      description: "Automatically isolates infected nodes and applies countermeasures within milliseconds.",
      icon: <Zap className="w-6 h-6" />,
      color: "from-orange-500 to-red-500"
    },
    {
      title: "Continuous Monitoring",
      description: "24/7 deep packet inspection and behavioral monitoring across all layers of the network.",
      icon: <Server className="w-6 h-6" />,
      color: "from-cyan-500 to-teal-500"
    },
    {
      icon: <Brain className="w-8 h-8" />,
      title: "AI Threat Hunter",
      description: "Advanced neural networks that hunt down sophisticated malware, zero-day exploits, and APTs before they can cause damage.",
      color: "from-red-500 to-red-700"
    },
    {
      icon: <Eye className="w-8 h-8" />,
      title: "Deep Packet Inspection",
      description: "Microscopic analysis of every byte of network traffic to detect hidden payloads and encrypted threats.",
      color: "from-orange-500 to-orange-700"
    },
    {
      icon: <Zap className="w-8 h-8" />,
      title: "Instant Kill Switch",
      description: "Millisecond response time to isolate and neutralize threats before they can spread or execute.",
      color: "from-yellow-500 to-yellow-700"
    },
    {
      icon: <Lock className="w-8 h-8" />,
      title: "Fortress Mode",
      description: "Impenetrable defense system that creates multiple layers of protection against coordinated attacks.",
      color: "from-blue-500 to-blue-700"
    },
    {
      icon: <Activity className="w-8 h-8" />,
      title: "Behavioral Analysis",
      description: "Monitors user and system behavior patterns to detect insider threats and compromised accounts.",
      color: "from-purple-500 to-purple-700"
    },
    {
      icon: <Award className="w-8 h-8" />,
      title: "Threat Intelligence",
      description: "Real-time feeds from global threat databases to stay ahead of emerging attack vectors.",
      color: "from-green-500 to-green-700"
    }
  ];

  const stats = [
    { number: "99.97%", label: "Threat Elimination Rate", color: "text-green-400" },
    { number: "0.3ms", label: "Detection Speed", color: "text-blue-400" },
    { number: "2.1M+", label: "Threats Blocked Daily", color: "text-red-400" },
    { number: "24/7/365", label: "Active Protection", color: "text-yellow-400" }
  ];

  type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  const getSeverityColor = (severity: SeverityLevel): string => {
    switch (severity) {
      case 'CRITICAL':
        return 'text-red-400 bg-red-900/20 border-red-500/30';
      case 'HIGH':
        return 'text-orange-400 bg-orange-900/20 border-orange-500/30';
      case 'MEDIUM':
        return 'text-yellow-400 bg-yellow-900/20 border-yellow-500/30';
      case 'LOW':
        return 'text-green-400 bg-green-900/20 border-green-500/30';
      default:
        return 'text-gray-400 bg-gray-900/20 border-gray-500/30';
    }
  };

  const backgroundPattern = `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23dc2626' fill-opacity='0.05'%3E%3Ccircle cx='30' cy='30' r='2'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`;

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Navigation */}
      <nav className="fixed top-0 w-full bg-black/95 backdrop-blur-sm border-b border-red-900/30 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <div className="bg-gradient-to-r from-red-600 to-red-800 p-2 rounded-lg animate-pulse">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <span className="text-xl font-bold text-white">VIRUS<span className="text-red-500">SHIELD</span></span>
            </div>
            
            <div className="hidden md:flex items-center space-x-8">
              <a href="#threats" className="text-gray-300 hover:text-red-400 transition-colors">Active Threats</a>
              <a href="#defense" className="text-gray-300 hover:text-red-400 transition-colors">Defense Systems</a>
              <a href="#monitor" className="text-gray-300 hover:text-red-400 transition-colors">Live Monitor</a>
              <button className="bg-gradient-to-r from-red-600 to-red-800 text-white px-6 py-2 rounded-lg hover:from-red-700 hover:to-red-900 transition-all transform hover:scale-105">
                ACTIVATE SHIELD
              </button>
            </div>

            <button 
              className="md:hidden text-white"
              onClick={() => setIsMenuOpen(!isMenuOpen)}
            >
              {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>

        {/* Mobile menu */}
        {isMenuOpen && (
          <div className="md:hidden bg-black/95 border-t border-red-900/30">
            <div className="px-4 py-2 space-y-2">
              <a href="#threats" className="block py-2 text-gray-300">Active Threats</a>
              <a href="#defense" className="block py-2 text-gray-300">Defense Systems</a>
              <a href="#monitor" className="block py-2 text-gray-300">Live Monitor</a>
              <button className="w-full bg-gradient-to-r from-red-600 to-red-800 text-white py-2 rounded-lg mt-4">
                ACTIVATE SHIELD
              </button>
            </div>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="pt-24 pb-16 bg-gradient-to-br from-black via-red-950/20 to-black relative overflow-hidden">
        {/* {<div className={`absolute inset-0 animate-pulse`} style={{ backgroundImage: backgroundPattern }}></div> } */}
        <div
  className="absolute inset-0 animate-pulse pointer-events-none"
  style={{ backgroundImage: backgroundPattern }}
></div>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <div className="inline-flex items-center bg-red-900/30 text-red-400 px-4 py-2 rounded-full text-sm font-medium mb-6 border border-red-500/30 animate-pulse">
                <AlertTriangle className="w-4 h-4 mr-2" />
                THREAT LEVEL: MAXIMUM
              </div>
              
              <h1 className="text-4xl lg:text-6xl font-bold text-white mb-6 leading-tight">
                TOTAL VIRUS
                <span className="block text-red-500 animate-pulse">ANNIHILATION</span>
                <span className="block text-2xl lg:text-3xl text-gray-400 mt-2">AI Defense System</span>
              </h1>
              
              <p className="text-xl text-gray-300 mb-8 leading-relaxed">
                The most aggressive AI-powered cybersecurity system ever created. Designed to hunt, identify, and 
                <span className="text-red-400 font-bold"> DESTROY </span>
                every form of digital threat before it can strike.
              </p>
              
              <div className="flex flex-col sm:flex-row gap-4">
                <button className="bg-gradient-to-r from-red-600 to-red-800 text-white px-8 py-4 rounded-lg text-lg font-bold hover:from-red-700 hover:to-red-900 transition-all duration-200 transform hover:scale-105 flex items-center justify-center shadow-lg shadow-red-500/25">
                  DEPLOY DEFENSE
                  <ArrowRight className="w-5 h-5 ml-2" />
                </button>
                <button className="border border-red-500 text-red-400 px-8 py-4 rounded-lg text-lg font-medium hover:bg-red-900/20 transition-colors">
                  VIEW THREAT MAP
                </button>
              </div>
            </div>
            
            <div className="relative">
              <div className="bg-gray-900/80 rounded-2xl shadow-2xl p-6 border border-red-500/30 backdrop-blur-sm">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-bold text-white flex items-center">
                    <div className="w-3 h-3 bg-red-500 rounded-full animate-ping mr-2"></div>
                    LIVE THREAT DETECTION
                  </h3>
                  <div className="flex items-center text-red-400">
                    <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse mr-2"></div>
                    {isScanning ? 'SCANNING' : 'ACTIVE'}
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div className={`flex items-center justify-between p-3 rounded-lg border ${getSeverityColor(threats[currentThreat].severity)}`}>
                    <div className="flex items-center">
                      <div className="text-red-500 mr-3">
                        {threats[currentThreat].icon}
                      </div>
                      <div>
                        <div className="font-bold text-white">{threats[currentThreat].type}</div>
                        <div className="text-sm text-gray-400">Severity: {threats[currentThreat].severity}</div>
                      </div>
                    </div>
                    <div className="text-green-400 font-bold text-sm">{threats[currentThreat].status}</div>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4 pt-4">
                    <div className="text-center p-3 bg-red-900/20 rounded-lg border border-red-500/30">
                      <div className="text-2xl font-bold text-red-400">{detectionCount.toLocaleString()}</div>
                      <div className="text-xs text-gray-400">Threats Eliminated</div>
                    </div>
                    <div className="text-center p-3 bg-orange-900/20 rounded-lg border border-orange-500/30">
                      <div className="text-2xl font-bold text-orange-400">{activeThreats}</div>
                      <div className="text-xs text-gray-400">Active Threats</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div> 
       
       <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6">
{/* URL Scan */}
            <div className="bg-gray-900/70 rounded-2xl shadow-md p-6 text-center border border-blue-500/30">
              <h3 className="text-lg font-semibold mb-3">🔗 URL Scan</h3>
              <input
                type="text"
                placeholder="Enter URL..."
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                className="w-full p-2 rounded mb-3 bg-white text-black"
              />
              <button
                onClick={handleUrlScan}
                className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition"
              >
                Scan URL
              </button>
            </div>

            {/* PDF Scan */}
            <div className="bg-gray-900/70 rounded-2xl shadow-md p-6 text-center border border-green-500/30">
              <h3 className="text-lg font-semibold mb-3">📄 PDF Scan</h3>
              <input
                type="file"
                accept="application/pdf"
                onChange={onFileInputChange}
                className="w-full p-2 rounded mb-3 text-black"
              />
              <button
                onClick={handleFileScan}
                className="bg-green-600 text-white px-6 py-2 rounded-lg hover:bg-green-700 transition"
              >
                Scan PDF
              </button>
            </div>

            {/* Image Scan */}
            <div className="bg-gray-900/70 rounded-2xl shadow-md p-6 text-center border border-purple-500/30">
              <h3 className="text-lg font-semibold mb-3">🖼️ Image Scan</h3>
              <input
                type="file"
                accept="image/*"
                onChange={onImageInputChange}
                className="w-full p-2 rounded mb-3 text-black"
              />
              <button
                onClick={handleImageScan}
                className="bg-purple-600 text-white px-6 py-2 rounded-lg hover:bg-purple-700 transition"
              >
                Scan Image
              </button>
            </div>
          </div>

           {/* {scanResult && (
          <div className="mb-4 p-2 bg-red-600 text-white rounded text-center">
            {scanResult}
            </div>
          )} */}

          {/* Scan Result Display */}
{scanResults && (
  <div className="mt-6 p-4 rounded-xl bg-gray-900 text-white shadow-lg">
    <h3 className="text-lg font-bold mb-2">Scan Result</h3>
    <p><strong>Type:</strong> {scanResults.type}</p>
    <p><strong>Target:</strong> {scanResults.target}</p>
    <p><strong>Detections:</strong> {scanResults.detections}</p>
    <p><strong>Status:</strong> 
      <span className={`ml-2 px-2 py-1 rounded ${
        scanResults.status === "Clean" ? "bg-green-600" :
        scanResults.status === "Suspicious" ? "bg-yellow-600" : "bg-red-600"
      }`}>
        {scanResults.status}
      </span>
    </p>
    <p><strong>Date:</strong> {scanResults.date}</p>

    {/* Detailed Engine Detections */}
    {scanResults.analysisResults && (
      <div className="mt-4 overflow-auto max-h-60 bg-gray-800 p-4 rounded-lg">
        <h4 className="text-white font-semibold mb-2">Engine detections:</h4>
        <table className="w-full text-left text-sm text-gray-200">
          <thead>
            <tr>
              <th className="pb-1">Engine</th>
              <th className="pb-1">Category</th>
              <th className="pb-1">Result</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(scanResults.analysisResults).map(([key, val]: any) => (
              <tr key={key} className="border-t border-gray-700">
                <td className="py-1">{val.engine_name}</td>
                <td className={`py-1 font-semibold ${
                  val.category === 'malicious' ? 'text-red-500' :
                  val.category === 'suspicious' ? 'text-yellow-400' :
                  'text-green-400'
                }`}>{val.category}</td>
                <td className="py-1">{val.result || 'Clean'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </div>
)}


      </section>

      {/* Stats Section */}
      <section className="py-16 bg-gradient-to-r from-red-900 to-red-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <div key={index} className="text-center">
                <div className={`text-3xl lg:text-4xl font-bold mb-2 ${stat.color}`}>{stat.number}</div>
                <div className="text-red-200">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="defense" className="py-20 bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
              ADVANCED THREAT <span className="text-red-500">ELIMINATION</span> SYSTEMS
            </h2>
            <p className="text-xl text-gray-400 max-w-3xl mx-auto">
              Military-grade AI defense mechanisms designed to identify, isolate, and eliminate 
              even the most sophisticated cyber threats in real-time.
            </p>
          </div>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => (
              <div 
                key={index} 
                className="bg-black/50 p-8 rounded-xl border border-gray-700 hover:border-red-500/50 transition-all duration-300 transform hover:-translate-y-2 hover:shadow-lg hover:shadow-red-500/10 group"
              >
                <div className={`bg-gradient-to-r ${feature.color} w-16 h-16 rounded-lg flex items-center justify-center text-white mb-6 group-hover:scale-110 transition-transform`}>
                  {feature.icon}
                </div>
                <h3 className="text-xl font-bold text-white mb-4 group-hover:text-red-400 transition-colors">{feature.title}</h3>
                <p className="text-gray-400 leading-relaxed">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Threat Monitor Section */}
      <section id="monitor" className="py-20 bg-black">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl lg:text-4xl font-bold text-white mb-4">
              REAL-TIME <span className="text-red-500">THREAT</span> MONITORING
            </h2>
            <p className="text-xl text-gray-400 max-w-3xl mx-auto">
              24/7 surveillance of global threat landscape with instant response capabilities
            </p>
          </div>
          
          <div className="grid lg:grid-cols-3 gap-8">
            <div className="bg-gray-900/50 p-6 rounded-xl border border-red-500/30">
              <h3 className="text-lg font-bold text-red-400 mb-4 flex items-center">
                <Skull className="w-5 h-5 mr-2" />
                CRITICAL THREATS
              </h3>
              <div className="space-y-3">
                {threats.filter(t => t.severity === 'CRITICAL').map((threat, index) => (
                  <div key={index} className="flex items-center justify-between p-2 bg-red-900/20 rounded border border-red-500/30">
                    <div className="flex items-center">
                      <div className="text-red-500 mr-2">{threat.icon}</div>
                      <span className="text-white text-sm">{threat.type}</span>
                    </div>
                    <span className="text-green-400 text-xs font-bold">{threat.status}</span>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="bg-gray-900/50 p-6 rounded-xl border border-orange-500/30">
              <h3 className="text-lg font-bold text-orange-400 mb-4 flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2" />
                HIGH PRIORITY
              </h3>
              <div className="space-y-3">
                {threats.filter(t => t.severity === 'HIGH').map((threat, index) => (
                  <div key={index} className="flex items-center justify-between p-2 bg-orange-900/20 rounded border border-orange-500/30">
                    <div className="flex items-center">
                      <div className="text-orange-500 mr-2">{threat.icon}</div>
                      <span className="text-white text-sm">{threat.type}</span>
                    </div>
                    <span className="text-green-400 text-xs font-bold">{threat.status}</span>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="bg-gray-900/50 p-6 rounded-xl border border-green-500/30">
              <h3 className="text-lg font-bold text-green-400 mb-4 flex items-center">
                <CheckCircle className="w-5 h-5 mr-2" />
                SYSTEM STATUS
              </h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">AI Engine</span>
                  <span className="text-green-400 font-bold">ACTIVE</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Threat Database</span>
                  <span className="text-green-400 font-bold">UPDATED</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Network Shield</span>
                  <span className="text-green-400 font-bold">PROTECTED</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Response Time</span>
                  <span className="text-blue-400 font-bold">0.3ms</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-gradient-to-r from-red-900 via-red-800 to-red-900">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl lg:text-4xl font-bold text-white mb-6">
            ACTIVATE MAXIMUM PROTECTION
          </h2>
          <p className="text-xl text-red-100 mb-8">
            Don't let cyber threats destroy your digital assets. Deploy the most aggressive AI defense system available.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <button className="bg-black text-white px-8 py-4 rounded-lg text-lg font-bold hover:bg-gray-900 transition-all transform hover:scale-105 shadow-lg">
              DEPLOY NOW
            </button>
            <button className="border-2 border-white text-white px-8 py-4 rounded-lg text-lg font-bold hover:bg-white hover:text-red-800 transition-colors">
              VIEW DEMO
            </button>
          </div>
          
          <p className="text-red-200 mt-6">Instant deployment • Real-time protection • 24/7 monitoring</p>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-black py-12 border-t border-red-900/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-4 gap-8">
            <div>
              <div className="flex items-center space-x-3 mb-4">
                <div className="bg-gradient-to-r from-red-600 to-red-800 p-2 rounded-lg">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <span className="text-xl font-bold text-white">VIRUS<span className="text-red-500">SHIELD</span></span>
              </div>
              <p className="text-gray-400">
                The ultimate AI-powered cybersecurity defense system for total threat elimination.
              </p>
            </div>
            
            <div>
              <h3 className="text-white font-bold mb-4">DEFENSE SYSTEMS</h3>
              <div className="space-y-2">
                <a href="#" className="block text-gray-400 hover:text-red-400 transition-colors">Threat Hunter</a>
                <a href="#" className="block text-gray-400 hover:text-red-400 transition-colors">Kill Switch</a>
                <a href="#" className="block text-gray-400 hover:text-red-400 transition-colors">Fortress Mode</a>
              </div>
            </div>
            
            <div>
              <h3 className="text-white font-bold mb-4">MONITORING</h3>
              <div className="space-y-2">
                <a href="#" className="block text-gray-400 hover:text-red-400 transition-colors">Live Dashboard</a>
                <a href="#" className="block text-gray-400 hover:text-red-400 transition-colors">Threat Intelligence</a>
                <a href="#" className="block text-gray-400 hover:text-red-400 transition-colors">Alert System</a>
              </div>
            </div>
            
            <div>
              <h3 className="text-white font-bold mb-4">SUPPORT</h3>
              <div className="space-y-2">
                <a href="#" className="block text-gray-400 hover:text-red-400 transition-colors">Emergency Response</a>
                <a href="#" className="block text-gray-400 hover:text-red-400 transition-colors">Technical Support</a>
                <a href="#" className="block text-gray-400 hover:text-red-400 transition-colors">Contact</a>
              </div>
            </div>
          </div>
          
          <div className="border-t border-red-900/30 mt-8 pt-8 text-center">
            <p className="text-gray-400">
              © 2024 VIRUSSHIELD AI. Maximum Protection Guaranteed.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
