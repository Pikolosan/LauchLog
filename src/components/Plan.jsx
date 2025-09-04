import { useState, useEffect, useRef } from 'react'
import Sortable from 'sortablejs'

const Plan = () => {
  const [tasks, setTasks] = useState({ todo: [], inProgress: [], completed: [] })
  const [taskForm, setTaskForm] = useState({ title: '', description: '', dueDate: '' })
  
  const todoRef = useRef(null)
  const progressRef = useRef(null)
  const completedRef = useRef(null)
  const sortablesRef = useRef([])

  useEffect(() => {
    loadTasks()
  }, [])

  useEffect(() => {
    const timer = setTimeout(() => {
      initSortable()
    }, 100)
    
    return () => {
      clearTimeout(timer)
      sortablesRef.current.forEach(sortable => {
        try {
          sortable.destroy()
        } catch (e) {
          // Ignore destroy errors
        }
      })
      sortablesRef.current = []
    }
  }, [tasks])

  const loadTasks = () => {
    const savedTasks = JSON.parse(localStorage.getItem('placeTrackTasks')) || { todo: [], inProgress: [], completed: [] }
    setTasks(savedTasks)
  }

  const saveTasks = (newTasks) => {
    localStorage.setItem('placeTrackTasks', JSON.stringify(newTasks))
    setTasks(newTasks)
  }

  const initSortable = () => {
    // Clean up existing sortables
    sortablesRef.current.forEach(sortable => {
      try {
        sortable.destroy()
      } catch (e) {
        // Ignore destroy errors
      }
    })
    sortablesRef.current = []

    const containers = [
      { ref: todoRef, column: 'todo' },
      { ref: progressRef, column: 'inProgress' },
      { ref: completedRef, column: 'completed' }
    ]

    containers.forEach(({ ref, column }) => {
      if (ref.current) {
        const sortable = new Sortable(ref.current, {
          group: 'tasks',
          animation: 150,
          ghostClass: 'bg-gray-700',
          chosenClass: 'bg-gray-600',
          dragClass: 'bg-gray-500',
          // Prevent SortableJS from manipulating DOM directly
          sort: false,
          // Use clone instead of moving elements
          onStart: (evt) => {
            evt.item.style.opacity = '0.5'
          },
          onEnd: (evt) => {
            evt.item.style.opacity = ''
            
            const taskId = evt.item.getAttribute('data-id')
            const fromColumn = getColumnFromElement(evt.from)
            const toColumn = getColumnFromElement(evt.to)
            
            // Prevent default SortableJS behavior and handle with React
            if (fromColumn !== toColumn && taskId) {
              // Move back the DOM element to prevent conflicts
              if (evt.from !== evt.to) {
                evt.from.insertBefore(evt.item, evt.from.children[evt.oldIndex])
              }
              // Let React handle the state change
              moveTask(taskId, fromColumn, toColumn)
            }
          }
        })
        sortablesRef.current.push(sortable)
      }
    })
  }

  const getColumnFromElement = (element) => {
    if (element === todoRef.current) return 'todo'
    if (element === progressRef.current) return 'inProgress'
    if (element === completedRef.current) return 'completed'
    return 'todo'
  }

  const moveTask = (taskId, fromColumn, toColumn) => {
    if (fromColumn === toColumn) return
    
    setTasks(currentTasks => {
      const newTasks = { ...currentTasks }
      const taskIndex = newTasks[fromColumn].findIndex(task => task.id === taskId)
      
      if (taskIndex !== -1) {
        const task = { ...newTasks[fromColumn][taskIndex] }
        newTasks[fromColumn] = newTasks[fromColumn].filter(t => t.id !== taskId)
        newTasks[toColumn] = [...newTasks[toColumn], task]

        localStorage.setItem('placeTrackTasks', JSON.stringify(newTasks))
        return newTasks
      }
      return currentTasks
    })
  }

  const addTask = (e) => {
    e.preventDefault()
    
    if (!taskForm.title) return
    
    const task = {
      id: Date.now().toString(),
      title: taskForm.title,
      description: taskForm.description || '',
      dueDate: taskForm.dueDate || '',
      createdAt: new Date().toISOString()
    }
    
    const newTasks = { ...tasks }
    newTasks.todo.push(task)
    saveTasks(newTasks)
    
    setTaskForm({ title: '', description: '', dueDate: '' })
  }

  const deleteTask = (taskId) => {
    const newTasks = { ...tasks }
    for (const column of ['todo', 'inProgress', 'completed']) {
      const index = newTasks[column].findIndex(task => task.id === taskId)
      if (index !== -1) {
        newTasks[column].splice(index, 1)
        saveTasks(newTasks)
        break
      }
    }
  }

  const renderTask = (task) => {
    let dueDateDisplay = null
    if (task.dueDate) {
      const dueDate = new Date(task.dueDate)
      const today = new Date()
      today.setHours(0, 0, 0, 0)
      
      const isPast = dueDate < today
      const isToday = dueDate.toDateString() === today.toDateString()
      
      let dateClass = ''
      if (isPast) dateClass = 'text-danger'
      else if (isToday) dateClass = 'text-warning'
      else dateClass = 'text-info'
      
      dueDateDisplay = (
        <div className={`flex items-center ${dateClass} text-xs mt-3`}>
          <i className="fas fa-calendar-alt mr-2"></i>
          <span>Due: {dueDate.toLocaleDateString()}</span>
        </div>
      )
    }
    
    return (
      <div key={task.id} className="task-card p-4" data-id={task.id}>
        <div className="flex justify-between items-start mb-2">
          <h4 className="font-semibold text-primary text-sm">{task.title}</h4>
          <button 
            onClick={(e) => {
              e.stopPropagation()
              deleteTask(task.id)
            }}
            className="text-secondary hover:text-danger transition-colors p-1 rounded"
            title="Delete task"
          >
            <i className="fas fa-times text-xs"></i>
          </button>
        </div>
        {task.description && (
          <p className="text-sm text-secondary mt-2 leading-relaxed">{task.description}</p>
        )}
        {dueDateDisplay}
      </div>
    )
  }

  return (
    <section className="content-section">
      <h2 className="text-3xl font-bold mb-6">Task Planner</h2>
      
      {/* Add New Task Form */}
      <div className="card p-8 mb-8">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-2xl font-bold text-primary">Add New Task</h3>
          <i className="fas fa-plus-square text-info text-2xl"></i>
        </div>
        
        <form onSubmit={addTask} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Title</label>
              <input 
                type="text" 
                value={taskForm.title}
                onChange={(e) => setTaskForm({ ...taskForm, title: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" 
                placeholder="Task title" 
                required 
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Due Date</label>
              <input 
                type="date" 
                value={taskForm.dueDate}
                onChange={(e) => setTaskForm({ ...taskForm, dueDate: e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" 
              />
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Description</label>
            <textarea 
              rows="2" 
              value={taskForm.description}
              onChange={(e) => setTaskForm({ ...taskForm, description: e.target.value })}
              className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" 
              placeholder="Task description"
            ></textarea>
          </div>
          
          <div className="flex justify-end">
            <button type="submit" className="btn-success px-8 py-3">
              <i className="fas fa-plus mr-2"></i> Add Task
            </button>
          </div>
        </form>
      </div>
      
      {/* Kanban Board */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* To Do Column */}
        <div className="kanban-column p-6">
          <h3 className="text-xl font-bold mb-6 flex items-center">
            <i className="fas fa-list-ul mr-3 text-info text-lg"></i>
            To Do
            <span className="ml-auto status-applied text-sm px-3 py-1">{tasks.todo.length}</span>
          </h3>
          
          <div ref={todoRef} className="space-y-4 min-h-[300px]">
            {tasks.todo.length === 0 ? (
              <div className="text-secondary text-center py-12">
                <i className="fas fa-plus-circle text-3xl mb-3 opacity-50"></i>
                <p>No tasks here</p>
              </div>
            ) : (
              tasks.todo.map(renderTask)
            )}
          </div>
        </div>
        
        {/* In Progress Column */}
        <div className="kanban-column p-6">
          <h3 className="text-xl font-bold mb-6 flex items-center">
            <i className="fas fa-spinner mr-3 text-warning text-lg"></i>
            In Progress
            <span className="ml-auto status-interview text-sm px-3 py-1">{tasks.inProgress.length}</span>
          </h3>
          
          <div ref={progressRef} className="space-y-4 min-h-[300px]">
            {tasks.inProgress.length === 0 ? (
              <div className="text-secondary text-center py-12">
                <i className="fas fa-cog fa-spin text-3xl mb-3 opacity-50"></i>
                <p>No tasks here</p>
              </div>
            ) : (
              tasks.inProgress.map(renderTask)
            )}
          </div>
        </div>
        
        {/* Completed Column */}
        <div className="kanban-column p-6">
          <h3 className="text-xl font-bold mb-6 flex items-center">
            <i className="fas fa-check-circle mr-3 text-success text-lg"></i>
            Completed
            <span className="ml-auto status-placed text-sm px-3 py-1">{tasks.completed.length}</span>
          </h3>
          
          <div ref={completedRef} className="space-y-4 min-h-[300px]">
            {tasks.completed.length === 0 ? (
              <div className="text-secondary text-center py-12">
                <i className="fas fa-check-circle text-3xl mb-3 opacity-50"></i>
                <p>No tasks here</p>
              </div>
            ) : (
              tasks.completed.map(renderTask)
            )}
          </div>
        </div>
      </div>
    </section>
  )
}

export default Plan