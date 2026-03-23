import { useState } from "react";
import { NavLink } from "react-router-dom";
import { authApi } from "../../api";

const NAV = [
  { label: "Overview",          path: "",         dot: "bg-indigo-500", section: "main"  },
  { label: "OWASP scanner",     path: "owasp",    dot: "bg-purple-500", section: "tools" },
  { label: "Metadata analyzer", path: "metadata", dot: "bg-orange-500", section: "tools" },
  { label: "Log analyzer",      path: "logs",     dot: "bg-amber-500",  section: "tools" },
  { label: "PCAP analyzer",     path: "pcap",     dot: "bg-teal-500",   section: "tools" },
  { label: "Lab challenges",    path: "labs",     dot: "bg-gray-400",   section: "learn" },
];

const SECTIONS = { main: "Overview", tools: "Tools", learn: "Learn" };

export default function Sidebar({ user }) {
  const [collapsed, setCollapsed] = useState(false);
  const sections = [...new Set(NAV.map(n => n.section))];

  return (
    <aside className={`flex-shrink-0 bg-white border-r border-gray-100 flex flex-col h-screen transition-all duration-200 z-30 ${collapsed ? "w-14" : "w-52"}`}>

      <div className="px-3 py-4 border-b border-gray-100 flex items-center justify-between gap-2">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 bg-indigo-600 rounded-md flex items-center justify-center flex-shrink-0">
              <span className="text-white text-xs font-bold">F</span>
            </div>
            <div>
              <div className="text-sm font-semibold text-gray-900 leading-none">ForensiQ</div>
              <div className="text-xs text-gray-400 mt-0.5">Security toolkit</div>
            </div>
          </div>
        )}
        {collapsed && (
          <div className="w-6 h-6 bg-indigo-600 rounded-md flex items-center justify-center mx-auto">
            <span className="text-white text-xs font-bold">F</span>
          </div>
        )}
        <button
          onClick={() => setCollapsed(c => !c)}
          className="p-1 rounded-md hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition-colors flex-shrink-0"
          title={collapsed ? "Expand" : "Collapse"}
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            {collapsed
              ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 5l7 7-7 7M5 5l7 7-7 7" />
              : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 19l-7-7 7-7M19 19l-7-7 7-7" />
            }
          </svg>
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
        {sections.map(section => (
          <div key={section}>
            {!collapsed && (
              <div className="px-3 mb-1 text-xs font-medium text-gray-400 uppercase tracking-wider">
                {SECTIONS[section]}
              </div>
            )}
            {NAV.filter(n => n.section === section).map(({ label, path, dot }) => (
              <NavLink
                key={path}
                to={path}
                end={path === ""}
                title={collapsed ? label : undefined}
                className={({ isActive }) =>
                  `flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-all duration-100
                   ${collapsed ? "justify-center" : ""}
                   ${isActive
                     ? "bg-indigo-50 text-indigo-700 font-medium"
                     : "text-gray-600 hover:bg-gray-50 hover:text-gray-900"}`
                }
              >
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${dot}`} />
                {!collapsed && label}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div className="px-3 py-3 border-t border-gray-100">
        {!collapsed ? (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <div className="w-7 h-7 rounded-full bg-indigo-100 flex items-center justify-center flex-shrink-0">
                <span className="text-xs font-medium text-indigo-700">
                  {(user?.full_name?.[0] ?? user?.email?.[0] ?? "?").toUpperCase()}
                </span>
              </div>
              <div className="min-w-0">
                <div className="text-xs font-medium text-gray-700 truncate">{user?.full_name ?? "User"}</div>
                <div className="text-xs text-gray-400 truncate">{user?.email}</div>
              </div>
            </div>
            <button onClick={() => authApi.logout()} className="text-xs text-gray-400 hover:text-red-500 transition-colors">
              Sign out
            </button>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2">
            <div className="w-7 h-7 rounded-full bg-indigo-100 flex items-center justify-center">
              <span className="text-xs font-medium text-indigo-700">
                {(user?.full_name?.[0] ?? user?.email?.[0] ?? "?").toUpperCase()}
              </span>
            </div>
            <button onClick={() => authApi.logout()} title="Sign out" className="text-gray-400 hover:text-red-500 transition-colors">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
        )}
      </div>
    </aside>
  );
}