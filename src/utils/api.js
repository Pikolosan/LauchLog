// Use relative URL for API calls in production, localhost for development
const API_BASE_URL = '';

class ApiService {
  getAuthHeaders() {
    const token = localStorage.getItem('token');
    return token ? { 'Authorization': `Bearer ${token}` } : {};
  }

  async makeRequest(endpoint, options = {}) {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          ...this.getAuthHeaders(),
          ...options.headers,
        },
        ...options,
      });

      // --- ✅ handle network errors or server issues
      if (!response.ok) {
        // 500 errors might still return JSON — try parsing
        try {
          const errData = await response.json();
          if (errData.offline === true) {
            window.dispatchEvent(new Event('backend-offline'));
          }
        } catch {
          /* ignore parse errors */
        }

        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();

      // --- ✅ Detect backend fallback (MongoDB disconnected)
      if (data.offline === true) {
        window.dispatchEvent(new Event('backend-offline'));
      } else {
        window.dispatchEvent(new Event('backend-online'));
      }

      return data;
    } catch (error) {
      console.error('API request failed:', error);

      // --- ✅ Network-level errors (browser offline, fetch failed, etc.)
      window.dispatchEvent(new Event('backend-offline'));

      throw error;
    }
  }

  // --- API endpoints below remain unchanged ---

  async getUserData() {
    return this.makeRequest('/api/user-data');
  }

  async saveTimerSession(session) {
    return this.makeRequest('/api/timer-sessions', {
      method: 'POST',
      body: JSON.stringify({ session }),
    });
  }

  async updateTasks(tasks) {
    return this.makeRequest('/api/tasks', {
      method: 'PUT',
      body: JSON.stringify({ tasks }),
    });
  }

  async saveJob(job) {
    return this.makeRequest('/api/jobs', {
      method: 'POST',
      body: JSON.stringify({ job }),
    });
  }

  async updateJob(jobId, updatedJob) {
    return this.makeRequest(`/api/jobs/${jobId}`, {
      method: 'PUT',
      body: JSON.stringify({ updatedJob }),
    });
  }

  async deleteJob(jobId) {
    return this.makeRequest(`/api/jobs/${jobId}`, { method: 'DELETE' });
  }

  async updateDashboard(dashboardData) {
    return this.makeRequest('/api/dashboard', {
      method: 'PUT',
      body: JSON.stringify({ dashboardData }),
    });
  }

  async resetAllData() {
    return this.makeRequest('/api/reset', { method: 'DELETE' });
  }

  async getSubjects() {
    return this.makeRequest('/api/subjects');
  }

  async addSubject(subject) {
    return this.makeRequest('/api/subjects', {
      method: 'POST',
      body: JSON.stringify({ subject }),
    });
  }

  async removeSubject(subject) {
    return this.makeRequest(`/api/subjects/${encodeURIComponent(subject)}`, {
      method: 'DELETE',
    });
  }

  async getAdminUsers() {
    return this.makeRequest('/api/admin/users');
  }

  async getAdminStats() {
    return this.makeRequest('/api/admin/stats');
  }

  async deleteUser(userId) {
    return this.makeRequest(`/api/admin/users/${userId}`, { method: 'DELETE' });
  }

  async login(email, password) {
    return this.makeRequest('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async register(name, email, password) {
    return this.makeRequest('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password }),
    });
  }
}

export const apiService = new ApiService();