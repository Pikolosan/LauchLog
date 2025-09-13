import { useState, useEffect } from 'react'
import { useData } from './hooks/useData'
import Sidebar from './components/Sidebar'
import Dashboard from './components/Dashboard'
import Timer from './components/Timer'
import Plan from './components/Plan'
import Jobs from './components/Jobs'
import Cover from './components/Cover'
import Auth from './components/Auth'
import Admin from './components/Admin'

function App() {
  const [showCover, setShowCover] = useState(true)
  const [showAuth, setShowAuth] = useState(false)
  const [activeSection, setActiveSection] = useState('dashboard')
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [user, setUser] = useState(null)
  const [authChecked, setAuthChecked] = useState(false)
  const [isSidebarOpen, setIsSidebarOpen] = useState(false)
  
  // Only initialize data hook after authentication is confirmed
  const dataHook = useData(isAuthenticated)

  useEffect(() => {
    // Check if user is already logged in
    const token = localStorage.getItem('token')
    const savedUser = localStorage.getItem('user')
    
    if (token && savedUser) {
      setUser(JSON.parse(savedUser))
      setIsAuthenticated(true)
      setShowCover(false)
      setShowAuth(false)
    }
    setAuthChecked(true)
  }, [])

  const handleEnterApp = () => {
    setShowCover(false)
    setShowAuth(true)
  }

  const handleAuthSuccess = (userData, token) => {
    setUser(userData)
    setIsAuthenticated(true)
    setShowAuth(false)
  }

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    setUser(null)
    setIsAuthenticated(false)
    setShowCover(true)
    setShowAuth(false)
  }

  const renderActiveSection = () => {
    switch (activeSection) {
      case 'timer':
        return <Timer dataHook={dataHook} />
      case 'plan':
        return <Plan dataHook={dataHook} />
      case 'jobs':
        return <Jobs dataHook={dataHook} />
      case 'admin':
        return <Admin />
      default:
        return <Dashboard dataHook={dataHook} />
    }
  }

  // Show loading while checking authentication
  if (!authChecked) {
    return (
      <div className="min-h-screen bg-main-bg flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-soft-sky-blue mb-4 mx-auto"></div>
          <p className="text-secondary-text">Loading...</p>
        </div>
      </div>
    )
  }

  if (showCover) {
    return <Cover onEnter={handleEnterApp} />
  }

  if (showAuth && !isAuthenticated) {
    return <Auth onAuthSuccess={handleAuthSuccess} />
  }

  return (
    <div className="flex h-screen">
      {/* Mobile overlay */}
      {isSidebarOpen && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}
      
      <Sidebar 
        activeSection={activeSection} 
        setActiveSection={setActiveSection} 
        dataHook={dataHook}
        user={user}
        onLogout={handleLogout}
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
      />
      
      <main className="flex-1 lg:ml-64 p-4 lg:p-8 overflow-y-auto">
        {/* Mobile hamburger menu */}
        <button
          onClick={() => setIsSidebarOpen(true)}
          className="lg:hidden fixed top-4 left-4 z-30 p-2 rounded-lg bg-elevated-bg text-primary-text hover:bg-soft-sky-blue hover:bg-opacity-20 transition-all"
        >
          <i className="fas fa-bars text-lg"></i>
        </button>
        
        <div className="lg:mt-0 mt-16">
        {dataHook.loading ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-soft-sky-blue mb-4 mx-auto"></div>
              <p className="text-secondary-text">Loading your data...</p>
            </div>
          </div>
        ) : (
          renderActiveSection()
        )}
        </div>
      </main>
    </div>
  )
}

export default App