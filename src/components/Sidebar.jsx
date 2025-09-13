const Sidebar = ({ activeSection, setActiveSection, dataHook, user, onLogout, isOpen, onClose }) => {
  const handleResetData = async () => {
    if (window.confirm('Are you sure you want to reset all data? This action cannot be undone.')) {
      try {
        if (dataHook) {
          await dataHook.resetAllData()
        } else {
          localStorage.clear()
        }
        window.location.reload()
      } catch (error) {
        console.error('Failed to reset data:', error)
        localStorage.clear()
        window.location.reload()
      }
    }
  }

  return (
    <aside className={`sidebar w-64 h-screen fixed top-0 left-0 overflow-y-auto z-50 transition-transform duration-300 ease-in-out ${
      isOpen ? 'translate-x-0' : '-translate-x-full'
    } lg:translate-x-0`}>
      <div className="p-4 flex flex-col h-full">
        <div className="mb-10">
          <h1 className="text-3xl font-bold mb-2 welcome-gradient">LaunchLog</h1>
          <p className="text-sm text-secondary leading-relaxed">A launchpad for your career, logs all progress.</p>
        </div>
        
        <nav className="space-y-2 flex-grow">
          <button
            onClick={() => {
              setActiveSection('dashboard')
              onClose && onClose() // Close sidebar on mobile
            }}
            className={`nav-link flex items-center p-3 rounded-lg w-full text-left ${
              activeSection === 'dashboard' ? 'active-nav' : 'hover:bg-gray-800'
            }`}
          >
            <i className="fas fa-chart-line mr-3 w-5"></i>
            <span>Dashboard</span>
          </button>
          <button
            onClick={() => {
              setActiveSection('timer')
              onClose && onClose() // Close sidebar on mobile
            }}
            className={`nav-link flex items-center p-3 rounded-lg w-full text-left ${
              activeSection === 'timer' ? 'active-nav' : 'hover:bg-gray-800'
            }`}
          >
            <i className="fas fa-clock mr-3 w-5"></i>
            <span>Timer</span>
          </button>
          <button
            onClick={() => {
              setActiveSection('plan')
              onClose && onClose() // Close sidebar on mobile
            }}
            className={`nav-link flex items-center p-3 rounded-lg w-full text-left ${
              activeSection === 'plan' ? 'active-nav' : 'hover:bg-gray-800'
            }`}
          >
            <i className="fas fa-tasks mr-3 w-5"></i>
            <span>Plan</span>
          </button>
          <button
            onClick={() => {
              setActiveSection('jobs')
              onClose && onClose() // Close sidebar on mobile
            }}
            className={`nav-link flex items-center p-3 rounded-lg w-full text-left ${
              activeSection === 'jobs' ? 'active-nav' : 'hover:bg-gray-800'
            }`}
          >
            <i className="fas fa-briefcase mr-3 w-5"></i>
            <span>Jobs Tracker</span>
          </button>
          {user && user.role === 'admin' && (
            <button
              onClick={() => {
                setActiveSection('admin')
                onClose && onClose() // Close sidebar on mobile
              }}
              className={`nav-link flex items-center p-3 rounded-lg w-full text-left ${
                activeSection === 'admin' ? 'active-nav' : 'hover:bg-gray-800'
              }`}
            >
              <i className="fas fa-user-shield mr-3 w-5"></i>
              <span>Admin Panel</span>
            </button>
          )}
        </nav>
        
        <div className="mt-auto pt-6 border-t border-divider-lines space-y-3">
          {user && (
            <div className="p-3 bg-elevated-bg rounded-lg">
              <div className="flex items-center">
                <div className="w-8 h-8 bg-soft-sky-blue rounded-full flex items-center justify-center text-main-bg font-bold mr-3">
                  {user.name.charAt(0).toUpperCase()}
                </div>
                <div>
                  <p className="text-primary-text font-medium text-sm">{user.name}</p>
                  <p className="text-secondary-text text-xs">{user.email}</p>
                </div>
              </div>
            </div>
          )}
          <button 
            onClick={handleResetData}
            className="flex items-center p-3 text-danger hover:text-soft-coral-red w-full text-left rounded-lg transition-all hover:bg-elevated-bg"
          >
            <i className="fas fa-trash-alt mr-3 text-lg"></i>
            <span className="font-medium">Reset All Data</span>
          </button>
          <button 
            onClick={onLogout}
            className="flex items-center p-3 text-secondary-text hover:text-primary-text w-full text-left rounded-lg transition-all hover:bg-elevated-bg"
          >
            <i className="fas fa-sign-out-alt mr-3 text-lg"></i>
            <span className="font-medium">Logout</span>
          </button>
        </div>
      </div>
    </aside>
  )
}

export default Sidebar