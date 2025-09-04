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

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  // Get all user data
  async getUserData() {
    return this.makeRequest('/api/user-data');
  }

  // Save timer session
  async saveTimerSession(session) {
    return this.makeRequest('/api/timer-sessions', {
      method: 'POST',
      body: JSON.stringify({ session }),
    });
  }

  // Update tasks
  async updateTasks(tasks) {
    return this.makeRequest('/api/tasks', {
      method: 'PUT',
      body: JSON.stringify({ tasks }),
    });
  }

  // Save job application
  async saveJob(job) {
    return this.makeRequest('/api/jobs', {
      method: 'POST',
      body: JSON.stringify({ job }),
    });
  }

  // Update job application
  async updateJob(jobId, updatedJob) {
    return this.makeRequest(`/api/jobs/${jobId}`, {
      method: 'PUT',
      body: JSON.stringify({ updatedJob }),
    });
  }

  // Delete job application
  async deleteJob(jobId) {
    return this.makeRequest(`/api/jobs/${jobId}`, {
      method: 'DELETE',
    });
  }

  // Update dashboard data
  async updateDashboard(dashboardData) {
    return this.makeRequest('/api/dashboard', {
      method: 'PUT',
      body: JSON.stringify({ dashboardData }),
    });
  }

  // Reset all data
  async resetAllData() {
    return this.makeRequest('/api/reset', {
      method: 'DELETE',
    });
  }
}

export const apiService = new ApiService();