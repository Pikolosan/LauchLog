import { useState, useEffect } from 'react'

const Jobs = () => {
  const [jobs, setJobs] = useState([])
  const [filteredJobs, setFilteredJobs] = useState([])
  const [jobForm, setJobForm] = useState({
    title: '',
    company: '',
    dateApplied: '',
    status: 'Applied',
    notes: ''
  })
  const [statusFilter, setStatusFilter] = useState('All')
  const [sortBy, setSortBy] = useState('dateDesc')
  const [editingJobId, setEditingJobId] = useState(null)

  useEffect(() => {
    loadJobs()
  }, [])

  useEffect(() => {
    applyFiltersAndSort()
  }, [jobs, statusFilter, sortBy])

  const loadJobs = () => {
    const savedJobs = JSON.parse(localStorage.getItem('placeTrackJobs')) || []
    setJobs(savedJobs)
  }

  const saveJobs = (newJobs) => {
    localStorage.setItem('placeTrackJobs', JSON.stringify(newJobs))
    setJobs(newJobs)
  }

  const applyFiltersAndSort = () => {
    let filtered = jobs
    
    if (statusFilter !== 'All') {
      filtered = jobs.filter(job => job.status === statusFilter)
    }
    filtered.sort((a, b) => {
      switch(sortBy) {
        case 'dateAsc':
          return new Date(a.dateApplied) - new Date(b.dateApplied)
        case 'company':
          return a.company.localeCompare(b.company)
        case 'status':
          return a.status.localeCompare(b.status)
        case 'dateDesc':
        default:
          return new Date(b.dateApplied) - new Date(a.dateApplied)
      }
    })
    
    setFilteredJobs(filtered)
  }

  const addJob = (e) => {
    e.preventDefault()
    
    if (!jobForm.title || !jobForm.company || !jobForm.dateApplied) return
    
    const job = {
      id: editingJobId || Date.now().toString(),
      title: jobForm.title,
      company: jobForm.company,
      dateApplied: jobForm.dateApplied,
      status: jobForm.status,
      notes: jobForm.notes || '',
      createdAt: new Date().toISOString()
    }
    
    let newJobs
    if (editingJobId) {
      newJobs = jobs.map(j => j.id === editingJobId ? job : j)
      setEditingJobId(null)
    } else {
      newJobs = [...jobs, job]
    }
    
    saveJobs(newJobs)
    
    setJobForm({
      title: '',
      company: '',
      dateApplied: '',
      status: 'Applied',
      notes: ''
    })
  }

  const editJob = (jobId) => {
    const job = jobs.find(job => job.id === jobId)
    if (!job) return
    
    setJobForm({
      title: job.title,
      company: job.company,
      dateApplied: job.dateApplied,
      status: job.status,
      notes: job.notes
    })
    
    setEditingJobId(jobId)
  }

  const deleteJob = (jobId) => {
    const newJobs = jobs.filter(job => job.id !== jobId)
    saveJobs(newJobs)
  }

  const getStatusBadge = (status) => {
    const styles = {
      Applied: { class: 'status-applied', icon: 'fa-paper-plane' },
      Interview: { class: 'status-interview', icon: 'fa-calendar-check' },
      Rejected: { class: 'status-rejected', icon: 'fa-times-circle' },
      Placed: { class: 'status-placed', icon: 'fa-check-circle' }
    }
    
    const style = styles[status] || styles.Applied
    
    return (
      <span className={`${style.class} inline-flex items-center`}>
        <i className={`fas ${style.icon} mr-2`}></i>
        {status}
      </span>
    )
  }

  return (
    <section className="content-section">
      <h2 className="text-3xl font-bold mb-6">Job Applications Tracker</h2>
      
      {/* Add New Job Form */}
      <div className="card p-8 mb-8">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-2xl font-bold text-primary">
            {editingJobId ? 'Edit Job Application' : 'Add New Job Application'}
          </h3>
          <i className="fas fa-plus-circle text-info text-2xl"></i>
        </div>
        
        <form onSubmit={addJob} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Job Title</label>
              <input 
                type="text" 
                value={jobForm.title}
                onChange={(e) => setJobForm({ ...jobForm, title: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" 
                placeholder="Software Engineer" 
                required 
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Company</label>
              <input 
                type="text" 
                value={jobForm.company}
                onChange={(e) => setJobForm({ ...jobForm, company: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" 
                placeholder="Google" 
                required 
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Date Applied</label>
              <input 
                type="date" 
                value={jobForm.dateApplied}
                onChange={(e) => setJobForm({ ...jobForm, dateApplied: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" 
                required 
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Status</label>
              <select 
                value={jobForm.status}
                onChange={(e) => setJobForm({ ...jobForm, status: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" 
                required
              >
                <option value="Applied">Applied</option>
                <option value="Interview">Interview Scheduled</option>
                <option value="Rejected">Rejected</option>
                <option value="Placed">Placed</option>
              </select>
            </div>
            
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-400 mb-1">Notes</label>
              <textarea 
                rows="1" 
                value={jobForm.notes}
                onChange={(e) => setJobForm({ ...jobForm, notes: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" 
                placeholder="Any additional notes..."
              ></textarea>
            </div>
          </div>
          
          <div className="flex justify-end space-x-4">
            {editingJobId && (
              <button 
                type="button"
                onClick={() => {
                  setEditingJobId(null)
                  setJobForm({
                    title: '',
                    company: '',
                    dateApplied: '',
                    status: 'Applied',
                    notes: ''
                  })
                }}
                className="btn-secondary px-6 py-3"
              >
                Cancel
              </button>
            )}
            <button type="submit" className="btn-success px-8 py-3">
              <i className="fas fa-plus mr-2"></i> {editingJobId ? 'Update Job' : 'Add Job'}
            </button>
          </div>
        </form>
      </div>
      
      {/* Filter Options */}
      <div className="mb-8 flex flex-wrap gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-1">Filter by Status</label>
          <select 
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="All">All Status</option>
            <option value="Applied">Applied</option>
            <option value="Interview">Interview</option>
            <option value="Rejected">Rejected</option>
            <option value="Placed">Placed</option>
          </select>
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-1">Sort by</label>
          <select 
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="dateDesc">Date (Newest)</option>
            <option value="dateAsc">Date (Oldest)</option>
            <option value="company">Company</option>
            <option value="status">Status</option>
          </select>
        </div>
      </div>
      
      {/* Jobs List */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="text-left">
              <tr>
                <th className="px-6 py-5 font-semibold text-primary">Job Title</th>
                <th className="px-6 py-5 font-semibold text-primary">Company</th>
                <th className="px-6 py-5 font-semibold text-primary">Date Applied</th>
                <th className="px-6 py-5 font-semibold text-primary">Status</th>
                <th className="px-6 py-5 font-semibold text-primary">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredJobs.length === 0 ? (
                <tr>
                  <td colSpan="5" className="px-6 py-16 text-center text-secondary">
                    <i className="fas fa-briefcase text-4xl mb-4 opacity-50 block"></i>
                    <p>{statusFilter !== 'All' ? 'No jobs match the selected filter' : 'No job applications added yet'}</p>
                  </td>
                </tr>
              ) : (
                filteredJobs.map((job) => (
                  <tr key={job.id}>
                    <td className="px-6 py-5">
                      <div className="font-semibold text-primary">{job.title}</div>
                    </td>
                    <td className="px-6 py-5 text-secondary">{job.company}</td>
                    <td className="px-6 py-5 text-secondary">{new Date(job.dateApplied).toLocaleDateString()}</td>
                    <td className="px-6 py-5">
                      {getStatusBadge(job.status)}
                    </td>
                    <td className="px-6 py-5">
                      <div className="flex space-x-3">
                        <button 
                          onClick={() => editJob(job.id)}
                          className="p-2 text-info hover:text-success transition-colors rounded-lg hover:bg-elevated-bg"
                          title="Edit job"
                        >
                          <i className="fas fa-edit"></i>
                        </button>
                        <button 
                          onClick={() => deleteJob(job.id)}
                          className="p-2 text-danger hover:text-soft-coral-red transition-colors rounded-lg hover:bg-elevated-bg"
                          title="Delete job"
                        >
                          <i className="fas fa-trash-alt"></i>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}

export default Jobs