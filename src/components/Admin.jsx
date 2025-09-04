import { useState, useEffect } from 'react'
import { apiService } from '../utils/api'

const Admin = () => {
  const [users, setUsers] = useState([])
  const [stats, setStats] = useState({
    totalUsers: 0,
    totalSessions: 0,
    totalTasks: 0,
    systemStatus: 'Loading...'
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    loadAdminData()
  }, [])

  const loadAdminData = async () => {
    try {
      setLoading(true)
      const [usersData, statsData] = await Promise.all([
        apiService.makeRequest('/api/admin/users'),
        apiService.makeRequest('/api/admin/stats')
      ])
      setUsers(usersData)
      setStats(statsData)
      setError('')
    } catch (err) {
      console.error('Failed to load admin data:', err)
      setError('Failed to load admin data')
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteUser = async (userId, userName) => {
    if (window.confirm(`Are you sure you want to delete user "${userName}"? This action cannot be undone.`)) {
      try {
        await apiService.makeRequest(`/api/admin/users/${userId}`, { method: 'DELETE' })
        setUsers(users.filter(user => user._id !== userId && user.id !== userId))
        // Reload stats after deletion
        const statsData = await apiService.makeRequest('/api/admin/stats')
        setStats(statsData)
      } catch (err) {
        console.error('Failed to delete user:', err)
        setError('Failed to delete user')
      }
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-soft-sky-blue mb-4 mx-auto"></div>
          <p className="text-secondary-text">Loading admin data...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-primary-text">Admin Dashboard</h1>
        <button
          onClick={loadAdminData}
          className="px-4 py-2 bg-soft-sky-blue hover:bg-blue-400 text-main-bg rounded-lg transition-colors"
        >
          <i className="fas fa-sync-alt mr-2"></i>
          Refresh
        </button>
      </div>

      {error && (
        <div className="bg-danger bg-opacity-10 border border-danger text-danger px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-elevated-bg p-6 rounded-xl border border-divider-lines">
          <div className="flex items-center">
            <div className="p-3 bg-soft-sky-blue bg-opacity-20 rounded-lg">
              <i className="fas fa-users text-soft-sky-blue text-xl"></i>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-primary-text">{stats.totalUsers}</p>
              <p className="text-secondary-text">Total Users</p>
            </div>
          </div>
        </div>

        <div className="bg-elevated-bg p-6 rounded-xl border border-divider-lines">
          <div className="flex items-center">
            <div className="p-3 bg-purple-600 bg-opacity-20 rounded-lg">
              <i className="fas fa-clock text-purple-400 text-xl"></i>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-primary-text">{stats.totalSessions}</p>
              <p className="text-secondary-text">Focus Sessions</p>
            </div>
          </div>
        </div>

        <div className="bg-elevated-bg p-6 rounded-xl border border-divider-lines">
          <div className="flex items-center">
            <div className="p-3 bg-green-600 bg-opacity-20 rounded-lg">
              <i className="fas fa-tasks text-green-400 text-xl"></i>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-primary-text">{stats.totalTasks}</p>
              <p className="text-secondary-text">Total Tasks</p>
            </div>
          </div>
        </div>

        <div className="bg-elevated-bg p-6 rounded-xl border border-divider-lines">
          <div className="flex items-center">
            <div className="p-3 bg-orange-600 bg-opacity-20 rounded-lg">
              <i className="fas fa-server text-orange-400 text-xl"></i>
            </div>
            <div className="ml-4">
              <p className="text-lg font-bold text-primary-text">{stats.systemStatus}</p>
              <p className="text-secondary-text">System Status</p>
            </div>
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-elevated-bg rounded-xl border border-divider-lines overflow-hidden">
        <div className="p-6 border-b border-divider-lines">
          <h2 className="text-xl font-bold text-primary-text">User Management</h2>
          <p className="text-secondary-text mt-1">Manage all LaunchLog users</p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-main-bg">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-secondary-text uppercase tracking-wider">
                  User
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-secondary-text uppercase tracking-wider">
                  Email
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-secondary-text uppercase tracking-wider">
                  Role
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-secondary-text uppercase tracking-wider">
                  Created
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-secondary-text uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-divider-lines">
              {users.map((user) => (
                <tr key={user._id || user.id} className="hover:bg-main-bg transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="w-10 h-10 bg-soft-sky-blue rounded-full flex items-center justify-center text-main-bg font-bold">
                        {user.name.charAt(0).toUpperCase()}
                      </div>
                      <div className="ml-4">
                        <div className="text-sm font-medium text-primary-text">{user.name}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-primary-text">{user.email}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      user.role === 'admin' 
                        ? 'bg-purple-100 text-purple-800' 
                        : 'bg-gray-100 text-gray-800'
                    }`}>
                      {user.role || 'user'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-secondary-text">
                    {user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    {user.role !== 'admin' && (
                      <button
                        onClick={() => handleDeleteUser(user._id || user.id, user.name)}
                        className="text-danger hover:text-red-400 transition-colors"
                      >
                        <i className="fas fa-trash-alt mr-1"></i>
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {users.length === 0 && (
          <div className="text-center py-8">
            <p className="text-secondary-text">No users found</p>
          </div>
        )}
      </div>
    </div>
  )
}

export default Admin