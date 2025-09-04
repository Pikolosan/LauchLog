import { useState, useEffect, useRef } from 'react'

const Timer = ({ dataHook }) => {
  const [timerMode, setTimerMode] = useState('pomodoro')
  const [timeLeft, setTimeLeft] = useState(25 * 60)
  const [isRunning, setIsRunning] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [isBreakTime, setIsBreakTime] = useState(false)
  const [selectedSubject, setSelectedSubject] = useState('')
  const [sessions, setSessions] = useState([])
  const [timerStatus, setTimerStatus] = useState('Focus Time')
  
  const timerRef = useRef(null)
  const timerStartTimeRef = useRef(null)

  useEffect(() => {
    if (dataHook && dataHook.data) {
      setSessions(dataHook.data.timerSessions.slice(0, 10))
    }
  }, [dataHook?.data])

  useEffect(() => {
    if (timerMode === 'pomodoro') {
      setTimerStatus(isBreakTime ? 'Break Time' : 'Focus Time')
    } else {
      setTimerStatus('Stopwatch')
    }
  }, [timerMode, isBreakTime])

  const formatTime = (seconds) => {
    const hours = Math.floor(seconds / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    const secs = seconds % 60
    
    if (hours > 0) {
      return `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`
    }
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`
  }

  const updateProgress = () => {
    if (timerMode === 'pomodoro' && !isBreakTime) {
      const totalSeconds = 25 * 60
      return ((totalSeconds - timeLeft) / totalSeconds) * 100
    } else if (timerMode === 'pomodoro' && isBreakTime) {
      const totalSeconds = 5 * 60
      return ((totalSeconds - timeLeft) / totalSeconds) * 100
    }
    return 0
  }

  const saveSession = async () => {
    if (!selectedSubject || !dataHook) return
    
    let durationInSeconds
    if (timerMode === 'pomodoro' && !isBreakTime) {
      durationInSeconds = 25 * 60 - timeLeft
    } else if (timerMode === 'stopwatch') {
      durationInSeconds = timeLeft
    } else {
      return
    }

    if (durationInSeconds < 60) return

    // Convert seconds to minutes for storage (this is what the Dashboard expects)
    const durationInMinutes = Math.round(durationInSeconds / 60)

    const session = {
      id: Date.now().toString(),
      subject: selectedSubject,
      duration: durationInMinutes,
      date: new Date().toISOString()
    }

    try {
      await dataHook.saveTimerSession(session)
      setSessions(prev => [session, ...prev.slice(0, 9)])
    } catch (error) {
      console.error('Failed to save session:', error)
    }
  }

  const startTimer = () => {
    if (!selectedSubject) {
      alert('Please select a subject first')
      return
    }

    setIsRunning(true)
    setIsPaused(false)
    timerStartTimeRef.current = Date.now()

    if (timerMode === 'pomodoro') {
      timerRef.current = setInterval(() => {
        setTimeLeft(prev => {
          if (prev > 0) {
            return prev - 1
          } else {
            clearInterval(timerRef.current)
            
            if (!isBreakTime) {
              saveSession()
              setIsBreakTime(true)
              setTimeLeft(5 * 60)
              setTimeout(() => startTimer(), 100)
            } else {
              setIsBreakTime(false)
              setTimeLeft(25 * 60)
              setIsRunning(false)
              alert('Pomodoro cycle completed!')
            }
            return prev
          }
        })
      }, 1000)
    } else {
      timerRef.current = setInterval(() => {
        const elapsed = Math.floor((Date.now() - timerStartTimeRef.current) / 1000)
        setTimeLeft(elapsed)
      }, 1000)
    }
  }

  const pauseTimer = () => {
    clearInterval(timerRef.current)
    setIsPaused(true)
  }

  const resetTimer = () => {
    clearInterval(timerRef.current)
    setIsRunning(false)
    setIsPaused(false)
    
    if (timerMode === 'pomodoro') {
      setTimeLeft(25 * 60)
      setIsBreakTime(false)
    } else {
      if (timeLeft > 0) {
        saveSession()
      }
      setTimeLeft(0)
    }
  }

  const switchToPomodoro = () => {
    if (isRunning) resetTimer()
    setTimerMode('pomodoro')
    setTimeLeft(25 * 60)
    setIsBreakTime(false)
  }

  const switchToStopwatch = () => {
    if (isRunning) resetTimer()
    setTimerMode('stopwatch')
    setTimeLeft(0)
  }

  return (
    <section className="content-section">
      <h2 className="text-3xl font-bold mb-6">Focus Timer</h2>
      
      <div className="flex flex-col md:flex-row gap-8">
        {/* Timer Card */}
        <div className="card p-8 flex-1">
          <div className="mb-6">
            <label className="block text-sm font-semibold text-secondary mb-3">Select Subject</label>
            <select 
              value={selectedSubject}
              onChange={(e) => setSelectedSubject(e.target.value)}
              className="w-full"
            >
              <option value="">Select a subject...</option>
              <option value="Data Structures">Data Structures</option>
              <option value="Algorithms">Algorithms</option>
              <option value="System Design">System Design</option>
              <option value="Web Development">Web Development</option>
              <option value="Database">Database</option>
              <option value="Other">Other</option>
            </select>
          </div>

          <div className="mb-8">
            <label className="block text-sm font-semibold text-secondary mb-3">Timer Mode</label>
            <div className="flex space-x-4">
              <button 
                onClick={switchToPomodoro}
                className={`flex-1 py-3 px-4 rounded-xl font-medium transition-all ${
                  timerMode === 'pomodoro' 
                    ? 'btn-primary' 
                    : 'btn-secondary'
                }`}
              >
                <i className="fas fa-hourglass-half mr-2"></i> Pomodoro
              </button>
              <button 
                onClick={switchToStopwatch}
                className={`flex-1 py-3 px-4 rounded-xl font-medium transition-all ${
                  timerMode === 'stopwatch' 
                    ? 'btn-primary' 
                    : 'btn-secondary'
                }`}
              >
                <i className="fas fa-stopwatch mr-2"></i> Stopwatch
              </button>
            </div>
          </div>

          {/* Timer Display */}
          <div className="flex flex-col items-center mb-8">
            <div className="timer-display mb-4">{formatTime(timeLeft)}</div>
            <div className="text-lg text-info font-medium mb-6">{timerStatus}</div>
            <div className="w-full progress-bar h-3 mb-6">
              <div 
                className="progress-fill h-3 transition-all duration-500"
                style={{ width: `${updateProgress()}%` }}
              ></div>
            </div>
          </div>

          {/* Timer Controls */}
          <div className="flex justify-center space-x-4">
            <button 
              onClick={startTimer}
              disabled={isRunning && !isPaused}
              className="btn-success px-8 py-4 text-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <i className="fas fa-play mr-2"></i> {isPaused ? 'Resume' : 'Start'}
            </button>
            <button 
              onClick={pauseTimer}
              disabled={!isRunning || isPaused}
              className="btn-warning px-6 py-4 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <i className="fas fa-pause mr-2"></i> Pause
            </button>
            <button 
              onClick={resetTimer}
              disabled={!isRunning && !isPaused}
              className="btn-secondary px-6 py-4 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <i className="fas fa-redo mr-2"></i> Reset
            </button>
          </div>
        </div>

        {/* Session History */}
        <div className="card p-6 flex-1">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-semibold text-primary">Recent Sessions</h3>
            <i className="fas fa-history text-info text-lg"></i>
          </div>
          
          <div className="overflow-y-auto max-h-96">
            <div className="space-y-3">
              {sessions.length === 0 ? (
                <div className="text-secondary text-center py-12">
                  <i className="fas fa-clock text-4xl mb-4 opacity-50"></i>
                  <p>No sessions recorded yet</p>
                </div>
              ) : (
                sessions.map((session) => {
                  const date = new Date(session.date)
                  // session.duration is stored in minutes
                  const totalMinutes = session.duration
                  const hours = Math.floor(totalMinutes / 60)
                  const minutes = totalMinutes % 60
                  const timeText = hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`
                  
                  // Convert minutes to seconds for formatTime function
                  const timeInSeconds = totalMinutes * 60
                  
                  return (
                    <div key={session.id} className="stat-card mb-3">
                      <div className="flex justify-between items-center mb-2">
                        <span className="font-semibold text-primary">{session.subject}</span>
                        <span className="text-sm text-secondary">{date.toLocaleDateString()}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-success flex items-center">
                          <i className="fas fa-clock mr-2"></i> {timeText}
                        </span>
                        <span className="status-applied text-xs px-3 py-1">{formatTime(timeInSeconds)}</span>
                      </div>
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

export default Timer