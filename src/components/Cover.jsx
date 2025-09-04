import { useState } from 'react'

const Cover = ({ onEnter }) => {
  const [isAnimating, setIsAnimating] = useState(false)

  const handleEnter = () => {
    setIsAnimating(true)
    setTimeout(() => {
      onEnter()
    }, 800)
  }

  return (
    <div className={`cover-page ${isAnimating ? 'cover-exit' : ''}`}>
      <div className="cover-content">
        {/* Background Elements */}
        <div className="cover-bg-elements">
          <div className="floating-element element-1">
            <i className="fas fa-rocket"></i>
          </div>
          <div className="floating-element element-2">
            <i className="fas fa-chart-line"></i>
          </div>
          <div className="floating-element element-3">
            <i className="fas fa-target"></i>
          </div>
          <div className="floating-element element-4">
            <i className="fas fa-briefcase"></i>
          </div>
          <div className="floating-element element-5">
            <i className="fas fa-clock"></i>
          </div>
          <div className="floating-element element-6">
            <i className="fas fa-trophy"></i>
          </div>
        </div>

        {/* Main Content */}
        <div className="cover-main">
          <div className="cover-logo">
            <div className="logo-icon">
              <i className="fas fa-rocket"></i>
            </div>
            <h1 className="logo-text">LaunchLog</h1>
          </div>

          <div className="cover-tagline">
            <p className="tagline-main">Like a launchpad for your career</p>
            <p className="tagline-sub">logs all progress.</p>
          </div>

          <div className="cover-features">
            <div className="feature-item">
              <i className="fas fa-chart-line"></i>
              <span>Track Progress</span>
            </div>
            <div className="feature-item">
              <i className="fas fa-clock"></i>
              <span>Focus Timer</span>
            </div>
            <div className="feature-item">
              <i className="fas fa-tasks"></i>
              <span>Task Planner</span>
            </div>
            <div className="feature-item">
              <i className="fas fa-briefcase"></i>
              <span>Job Tracker</span>
            </div>
          </div>

          <button 
            className="cover-enter-btn"
            onClick={handleEnter}
            disabled={isAnimating}
          >
            <span>Launch Your Career</span>
            <i className="fas fa-arrow-right"></i>
          </button>

          <div className="cover-footer">
            <p>Start tracking your career journey today</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Cover