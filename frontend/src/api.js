import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

export const authApi = {
  register: (email, password, full_name) =>
    api.post("/auth/register", { email, password, full_name }),

  login: async (email, password) => {
    const { data } = await api.post("/auth/login", { email, password });
    localStorage.setItem("token", data.access_token);
    const me = await api.get("/auth/me");
    localStorage.setItem("user", JSON.stringify(me.data));
    return me.data;
  },

  logout: () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    window.location.href = "/login";
  },

  me: () => api.get("/auth/me"),
};

export const dashboardApi = {
  stats: () => api.get("/dashboard/stats").then((r) => r.data),
  recentFindings: () => api.get("/dashboard/recent-findings").then((r) => r.data),
};

export const owaspApi = {
  scan: (url, checks) =>
    api.post("/scan/owasp", { url, checks }).then((r) => r.data),
};

export const metadataApi = {
  analyze: (file) => {
    const form = new FormData();
    form.append("file", file);
    return api.post("/scan/metadata", form, {
      headers: { "Content-Type": "multipart/form-data" },
    }).then((r) => r.data);
  },
};

export const logApi = {
  analyzeFile: (file, log_type = "auto") => {
    const form = new FormData();
    form.append("file", file);
    form.append("log_type", log_type);
    return api.post("/scan/logs", form, {
      headers: { "Content-Type": "multipart/form-data" },
    }).then((r) => r.data);
  },

  analyzeText: (content, log_type = "auto") => {
    const form = new FormData();
    form.append("content", content);
    form.append("log_type", log_type);
    return api.post("/scan/logs", form, {
      headers: { "Content-Type": "multipart/form-data" },
    }).then((r) => r.data);
  },
};

export const pcapApi = {
  analyze: (file) => {
    const form = new FormData();
    form.append("file", file);
    return api.post("/scan/pcap", form, {
      headers: { "Content-Type": "multipart/form-data" },
    }).then((r) => r.data);
  },
};

export const scanApi = {
  history: () => api.get("/scan/history").then((r) => r.data),
  get: (id) => api.get(`/scan/${id}`).then((r) => r.data),
};

export default api;