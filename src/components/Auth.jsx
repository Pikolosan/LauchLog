import { useState, useEffect } from 'react'
import zxcvbn from 'zxcvbn'

const Auth = ({ onAuthSuccess }) => {
  const [isLogin, setIsLogin] = useState(true)
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: ''
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [passwordStrength, setPasswordStrength] = useState(null)
  const [passwordErrors, setPasswordErrors] = useState([])

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
        // Handle different error response formats
        let errorMessage;
        if (data.errors && Array.isArray(data.errors)) {
          // Validation errors from express-validator
          errorMessage = data.errors.map(err => err.msg).join('. ');
        } else if (data.error) {
          // Single error message
          errorMessage = data.error;
        } else {
          errorMessage = 'Authentication failed';
        }
        throw new Error(errorMessage);
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

  const validatePassword = (password) => {
    const errors = [];
    
    if (password.length < 12) {
      errors.push('At least 12 characters long');
    }
    
    if (!/[a-z]/.test(password)) {
      errors.push('One lowercase letter');
    }
    
    if (!/[A-Z]/.test(password)) {
      errors.push('One uppercase letter');
    }
    
    if (!/\d/.test(password)) {
      errors.push('One number');
    }
    
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('One special character');
    }
    
    return errors;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Real-time password validation for registration
    if (name === 'password' && !isLogin && value) {
      const strength = zxcvbn(value);
      setPasswordStrength(strength);
      setPasswordErrors(validatePassword(value));
    } else if (name === 'password' && !isLogin && !value) {
      setPasswordStrength(null);
      setPasswordErrors([]);
    }
  };

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
                className={`w-full px-4 py-3 bg-main-bg border rounded-lg focus:ring-2 focus:border-transparent text-primary-text placeholder-secondary-text ${
                  !isLogin && formData.password ? (
                    passwordErrors.length === 0 ? 'border-green-500 focus:ring-green-500' : 'border-red-500 focus:ring-red-500'
                  ) : 'border-divider-lines focus:ring-soft-sky-blue'
                }`}
                placeholder="Enter your password"
                minLength={isLogin ? 1 : 12}
              />
              
              {!isLogin && formData.password && (
                <div className="mt-3">
                  {/* Password Strength Meter */}
                  {passwordStrength && (
                    <div className="mb-3">
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-xs text-secondary-text">Password Strength:</span>
                        <span className={`text-xs font-medium ${
                          passwordStrength.score === 0 ? 'text-red-500' :
                          passwordStrength.score === 1 ? 'text-orange-500' :
                          passwordStrength.score === 2 ? 'text-yellow-500' :
                          passwordStrength.score === 3 ? 'text-blue-500' :
                          'text-green-500'
                        }`}>
                          {['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][passwordStrength.score]}
                        </span>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full transition-all duration-300 ${
                            passwordStrength.score === 0 ? 'bg-red-500 w-1/5' :
                            passwordStrength.score === 1 ? 'bg-orange-500 w-2/5' :
                            passwordStrength.score === 2 ? 'bg-yellow-500 w-3/5' :
                            passwordStrength.score === 3 ? 'bg-blue-500 w-4/5' :
                            'bg-green-500 w-full'
                          }`}
                        />
                      </div>
                    </div>
                  )}
                  
                  {/* Password Requirements */}
                  <div className="space-y-1">
                    <p className="text-xs font-medium text-secondary-text mb-2">Password must include:</p>
                    {[
                      { check: formData.password.length >= 12, text: 'At least 12 characters' },
                      { check: /[a-z]/.test(formData.password), text: 'One lowercase letter' },
                      { check: /[A-Z]/.test(formData.password), text: 'One uppercase letter' },
                      { check: /\d/.test(formData.password), text: 'One number' },
                      { check: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(formData.password), text: 'One special character' }
                    ].map((req, index) => (
                      <div key={index} className={`flex items-center space-x-2 text-xs ${
                        req.check ? 'text-green-400' : 'text-red-400'
                      }`}>
                        <i className={`fas ${req.check ? 'fa-check' : 'fa-times'}`} />
                        <span>{req.text}</span>
                      </div>
                    ))}
                  </div>
                  
                  {/* Password Feedback */}
                  {passwordStrength && passwordStrength.feedback.warning && (
                    <div className="mt-2 p-2 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded text-xs text-yellow-400">
                      <i className="fas fa-exclamation-triangle mr-1" />
                      {passwordStrength.feedback.warning}
                    </div>
                  )}
                  
                  {passwordStrength && passwordStrength.feedback.suggestions.length > 0 && (
                    <div className="mt-2 p-2 bg-blue-500 bg-opacity-10 border border-blue-500 rounded text-xs text-blue-400">
                      <i className="fas fa-lightbulb mr-1" />
                      {passwordStrength.feedback.suggestions[0]}
                    </div>
                  )}
                </div>
              )}
              
              {isLogin && (
                <p className="mt-1 text-xs text-secondary-text">
                  Enter your password to sign in
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