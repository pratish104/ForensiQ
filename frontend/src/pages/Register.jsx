import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { authApi } from "../api";

export default function Register() {
  const navigate = useNavigate();
  const [form, setForm]       = useState({ email: "", password: "", full_name: "" });
  const [error, setError]     = useState("");
  const [loading, setLoading] = useState(false);

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }));

  const submit = async (e) => {
    e.preventDefault();
    setError(""); setLoading(true);
    try {
      await authApi.register(form.email, form.password, form.full_name);
      await authApi.login(form.email, form.password);
      navigate("/dashboard");
    } catch (err) {
      setError(err?.response?.data?.detail || "Registration failed");
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
            Start your security<br />learning journey
          </h1>
          <p className="text-indigo-200 text-sm leading-relaxed">
            ForensiQ gives you a full security testing toolkit and guided lab challenges — built to help you learn, practice, and showcase your skills.
          </p>
        </div>
        <p className="text-indigo-300 text-xs">Free to use · No credit card required</p>
      </div>

      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-sm">
          <div className="mb-8">
            <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center mb-4 lg:hidden">
              <span className="text-white font-bold">F</span>
            </div>
            <h2 className="text-2xl font-semibold text-gray-900">Create account</h2>
            <p className="text-sm text-gray-500 mt-1">Join ForensiQ — it's free</p>
          </div>

          {error && (
            <div className="mb-4 bg-red-50 border border-red-200 text-red-700 text-sm px-4 py-3 rounded-lg">
              {error}
            </div>
          )}

          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1.5">Full name</label>
              <input className="input" placeholder="Your name"
                value={form.full_name} onChange={set("full_name")} />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1.5">Email</label>
              <input className="input" type="email" placeholder="you@example.com"
                value={form.email} onChange={set("email")} required />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1.5">Password</label>
              <input className="input" type="password" placeholder="••••••••"
                value={form.password} onChange={set("password")} required />
            </div>
            <button className="btn-primary w-full justify-center py-2.5" type="submit" disabled={loading}>
              {loading
                ? <><span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />Creating account…</>
                : "Create account"}
            </button>
          </form>

          <p className="text-sm text-gray-500 text-center mt-6">
            Already have an account?{" "}
            <Link to="/login" className="text-indigo-600 font-medium hover:underline">Sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}