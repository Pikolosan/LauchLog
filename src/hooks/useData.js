import { useState, useEffect } from 'react';
import { apiService } from '../utils/api';

export const useData = (isAuthenticated = false) => {
  const [data, setData] = useState({
    timerSessions: [],
    tasks: { todo: [], doing: [], done: [] },
    jobs: [],
    dashboardData: {
      totalHours: 0,
      completedTasks: 0,
      activeApplications: 0,
      sessionsThisWeek: 0
    }
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Load data from MongoDB only when authenticated
  useEffect(() => {
    if (isAuthenticated) {
      loadUserData();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthenticated]);

  const loadUserData = async () => {
    try {
      setLoading(true);
      const userData = await apiService.getUserData();
      setData(userData);
      setError(null);
    } catch (err) {
      console.error('Failed to load user data:', err);
      setError('Failed to load user data');
      // Fallback to localStorage if API fails
      loadFromLocalStorage();
    } finally {
      setLoading(false);
    }
  };

  const loadFromLocalStorage = () => {
    try {
      const timerSessions = JSON.parse(localStorage.getItem('timerSessions') || '[]');
      const tasks = JSON.parse(localStorage.getItem('kanbanTasks') || '{"todo":[],"doing":[],"done":[]}');
      const jobs = JSON.parse(localStorage.getItem('jobApplications') || '[]');
      const dashboardData = {
        totalHours: timerSessions.reduce((total, session) => total + (session.duration || 0), 0) / 60,
        completedTasks: tasks.done?.length || 0,
        activeApplications: jobs.filter(job => job.status !== 'Rejected' && job.status !== 'Placed').length,
        sessionsThisWeek: timerSessions.filter(session => {
          const sessionDate = new Date(session.date);
          const weekAgo = new Date();
          weekAgo.setDate(weekAgo.getDate() - 7);
          return sessionDate >= weekAgo;
        }).length
      };
      
      setData({ timerSessions, tasks, jobs, dashboardData });
    } catch (err) {
      console.error('Failed to load from localStorage:', err);
    }
  };

  // Save timer session
  const saveTimerSession = async (session) => {
    try {
      await apiService.saveTimerSession(session);
      setData(prev => ({
        ...prev,
        timerSessions: [...prev.timerSessions, session]
      }));
      updateDashboardData();
    } catch (err) {
      console.error('Failed to save timer session:', err);
      // Fallback to localStorage
      const sessions = [...data.timerSessions, session];
      localStorage.setItem('timerSessions', JSON.stringify(sessions));
      setData(prev => ({ ...prev, timerSessions: sessions }));
    }
  };

  // Update tasks
  const updateTasks = async (newTasks) => {
    try {
      await apiService.updateTasks(newTasks);
      setData(prev => ({ ...prev, tasks: newTasks }));
      updateDashboardData();
    } catch (err) {
      console.error('Failed to update tasks:', err);
      // Fallback to localStorage
      localStorage.setItem('kanbanTasks', JSON.stringify(newTasks));
      setData(prev => ({ ...prev, tasks: newTasks }));
    }
  };

  // Save job
  const saveJob = async (job) => {
    try {
      await apiService.saveJob(job);
      setData(prev => ({
        ...prev,
        jobs: [...prev.jobs, job]
      }));
      updateDashboardData();
    } catch (err) {
      console.error('Failed to save job:', err);
      // Fallback to localStorage
      const jobs = [...data.jobs, job];
      localStorage.setItem('jobApplications', JSON.stringify(jobs));
      setData(prev => ({ ...prev, jobs }));
    }
  };

  // Update job
  const updateJob = async (jobId, updatedJob) => {
    try {
      await apiService.updateJob(jobId, updatedJob);
      setData(prev => ({
        ...prev,
        jobs: prev.jobs.map(job => job.id === jobId ? updatedJob : job)
      }));
      updateDashboardData();
    } catch (err) {
      console.error('Failed to update job:', err);
      // Fallback to localStorage
      const jobs = data.jobs.map(job => job.id === jobId ? updatedJob : job);
      localStorage.setItem('jobApplications', JSON.stringify(jobs));
      setData(prev => ({ ...prev, jobs }));
    }
  };

  // Delete job
  const deleteJob = async (jobId) => {
    try {
      await apiService.deleteJob(jobId);
      setData(prev => ({
        ...prev,
        jobs: prev.jobs.filter(job => job.id !== jobId)
      }));
      updateDashboardData();
    } catch (err) {
      console.error('Failed to delete job:', err);
      // Fallback to localStorage
      const jobs = data.jobs.filter(job => job.id !== jobId);
      localStorage.setItem('jobApplications', JSON.stringify(jobs));
      setData(prev => ({ ...prev, jobs }));
    }
  };

  // Update dashboard data
  const updateDashboardData = async () => {
    const newDashboardData = {
      totalHours: data.timerSessions.reduce((total, session) => total + (session.duration || 0), 0) / 60,
      completedTasks: data.tasks.done?.length || 0,
      activeApplications: data.jobs.filter(job => job.status !== 'Rejected' && job.status !== 'Placed').length,
      sessionsThisWeek: data.timerSessions.filter(session => {
        const sessionDate = new Date(session.date);
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        return sessionDate >= weekAgo;
      }).length
    };

    try {
      await apiService.updateDashboard(newDashboardData);
      setData(prev => ({ ...prev, dashboardData: newDashboardData }));
    } catch (err) {
      console.error('Failed to update dashboard data:', err);
      setData(prev => ({ ...prev, dashboardData: newDashboardData }));
    }
  };

  // Reset all data
  const resetAllData = async () => {
    try {
      await apiService.resetAllData();
      const defaultData = {
        timerSessions: [],
        tasks: { todo: [], doing: [], done: [] },
        jobs: [],
        dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 }
      };
      setData(defaultData);
      
      // Also clear localStorage as backup
      localStorage.clear();
    } catch (err) {
      console.error('Failed to reset data:', err);
      // Fallback to localStorage clear
      localStorage.clear();
      const defaultData = {
        timerSessions: [],
        tasks: { todo: [], doing: [], done: [] },
        jobs: [],
        dashboardData: { totalHours: 0, completedTasks: 0, activeApplications: 0, sessionsThisWeek: 0 }
      };
      setData(defaultData);
    }
  };

  return {
    data,
    loading,
    error,
    saveTimerSession,
    updateTasks,
    saveJob,
    updateJob,
    deleteJob,
    resetAllData,
    refreshData: loadUserData
  };
};