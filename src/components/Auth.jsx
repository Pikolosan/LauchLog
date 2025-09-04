import { useState } from 'react'

const Auth = ({ onAuthSuccess }) => {
  const [isLogin, setIsLogin] = useState(true)
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: ''
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register'
      const body = isLogin 
        ? { email: formData.email, password: formData.password }
        : formData

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed')
      }

      // Store token and user info
      localStorage.setItem('token', data.token)
      localStorage.setItem('user', JSON.stringify(data.user))
      
      onAuthSuccess(data.user, data.token)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleChange = (e) => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value
    }))
  }

  return (
    <div className="min-h-screen bg-main-bg flex items-center justify-center p-8">
      <div className="w-full max-w-md">
        <div className="bg-elevated-bg backdrop-blur-sm rounded-2xl p-8 border border-divider-lines shadow-xl">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-soft-sky-blue mb-2">LaunchLog</h1>
            <p className="text-secondary-text">
              {isLogin ? 'Welcome back' : 'Create your account'}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {!isLogin && (
              <div>
                <label className="block text-sm font-medium text-secondary-text mb-2">
                  Full Name
                </label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  required={!isLogin}
                  className="w-full px-4 py-3 bg-main-bg border border-divider-lines rounded-lg focus:ring-2 focus:ring-soft-sky-blue focus:border-transparent text-primary-text placeholder-secondary-text"
                  placeholder="Enter your full name"
                />
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-secondary-text mb-2">
                Email Address
              </label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 bg-main-bg border border-divider-lines rounded-lg focus:ring-2 focus:ring-soft-sky-blue focus:border-transparent text-primary-text placeholder-secondary-text"
                placeholder="Enter your email"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-secondary-text mb-2">
                Password
              </label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 bg-main-bg border border-divider-lines rounded-lg focus:ring-2 focus:ring-soft-sky-blue focus:border-transparent text-primary-text placeholder-secondary-text"
                placeholder="Enter your password"
                minLength={6}
              />
              {!isLogin && (
                <p className="mt-1 text-xs text-secondary-text">
                  Password must be at least 6 characters
                </p>
              )}
            </div>

            {error && (
              <div className="bg-danger bg-opacity-10 border border-danger text-danger px-4 py-3 rounded-lg">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-soft-sky-blue hover:bg-blue-400 text-main-bg font-medium py-3 px-4 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Please wait...' : (isLogin ? 'Sign In' : 'Create Account')}
            </button>
          </form>

          <div className="mt-6 text-center">
            <button
              type="button"
              onClick={() => {
                setIsLogin(!isLogin)
                setError('')
                setFormData({ email: '', password: '', name: '' })
              }}
              className="text-soft-sky-blue hover:text-blue-400 transition-colors"
            >
              {isLogin 
                ? "Don't have an account? Sign up" 
                : "Already have an account? Sign in"
              }
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Auth