import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { authApi } from "../api";

function getStoredUser() {
  try {
    const r = localStorage.getItem("user");
    return r ? JSON.parse(r) : null;
  } catch { return null; }
}

export function useAuth() {
  const navigate              = useNavigate();
  const [user, setUser]       = useState(getStoredUser);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const login = useCallback(async (email, password) => {
    setLoading(true); setError(null);
    try {
      const u = await authApi.login(email, password);
      setUser(u);
      navigate("/dashboard");
    } catch (err) {
      setError(err?.response?.data?.detail ?? "Login failed");
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  const register = useCallback(async (email, password, full_name) => {
    setLoading(true); setError(null);
    try {
      await authApi.register(email, password, full_name);
      await authApi.login(email, password);
      setUser(getStoredUser());
      navigate("/dashboard");
    } catch (err) {
      setError(err?.response?.data?.detail ?? "Registration failed");
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  const logout     = useCallback(() => { authApi.logout(); setUser(null); }, []);
  const clearError = useCallback(() => setError(null), []);

  return {
    user, loading, error,
    isAuthenticated: !!localStorage.getItem("token"),
    login, register, logout, clearError,
  };
}