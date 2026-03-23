import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { authApi } from "../api";

export default function Login() {
  const navigate = useNavigate();
  const [email, setEmail]       = useState("");
  const [password, setPassword] = useState("");
  const [error, setError]       = useState("");
  const [loading, setLoading]   = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError(""); setLoading(true);
    try {
      await authApi.login(email, password);
      navigate("/dashboard");
    } catch (err) {
      setError(err?.response?.data?.detail || "Invalid email or password");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex">
      <div className="hidden lg:flex lg:w-1/2 bg-indigo-600 flex-col justify-between p-12">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-white/20 rounded-lg flex items-center justify-center">
            <span className="text-white font-bold text-sm">F</span>
          </div>
          <span className="text-white font-semibold text-lg">ForensiQ</span>
        </div>
        <div>
          <h1 className="text-3xl font-semibold text-white mb-4 leading-snug">
            Web security testing<br />& digital forensics
          </h1>
          <div className="space-y-3">
            {[
              "OWASP Top 10 vulnerability scanner",
              "File metadata & EXIF analyzer",
              "Log anomaly detection",
              "Network traffic (PCAP) analysis",
              "Hands-on lab challenges",
            ].map(f => (
              <div key={f} className="flex items-center gap-2 text-indigo-100 text-sm">
                <div className="w-1.5 h-1.5 rounded-full bg-indigo-300 flex-shrink-0" />
                {f}
              </div>
            ))}
          </div>
        </div>
        <p className="text-indigo-300 text-xs">Built for learning & portfolio showcase</p>
      </div>

      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-sm">
          <div className="mb-8">
            <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center mb-4 lg:hidden">
              <span className="text-white font-bold">F</span>
            </div>
            <h2 className="text-2xl font-semibold text-gray-900">Welcome back</h2>
            <p className="text-sm text-gray-500 mt-1">Sign in to your ForensiQ account</p>
          </div>

          {error && (
            <div className="mb-4 bg-red-50 border border-red-200 text-red-700 text-sm px-4 py-3 rounded-lg">
              {error}
            </div>
          )}

          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1.5">Email</label>
              <input className="input" type="email" placeholder="you@example.com"
                value={email} onChange={e => setEmail(e.target.value)} required />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1.5">Password</label>
              <input className="input" type="password" placeholder="••••••••"
                value={password} onChange={e => setPassword(e.target.value)} required />
            </div>
            <button className="btn-primary w-full justify-center py-2.5" type="submit" disabled={loading}>
              {loading
                ? <><span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />Signing in…</>
                : "Sign in"}
            </button>
          </form>

          <p className="text-sm text-gray-500 text-center mt-6">
            No account?{" "}
            <Link to="/register" className="text-indigo-600 font-medium hover:underline">Create one</Link>
          </p>
        </div>
      </div>
    </div>
  );
}