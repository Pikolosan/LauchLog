# 🚀 LaunchLog

**Live Demo:** [Live on Render](https://lauchlog.onrender.com)

**Live Demo Video:** [Live Video](https://drive.google.com/file/d/18QAgNSx6b3wgevdnkPmjKNnhYWl-Ghv6/view?usp=sharing)

## Overview

LaunchLog is a career progress tracking application that serves as "a launchpad for your career, logs all progress." It's a React-based single-page application built with modern web technologies, featuring a dark theme with neon accents and focusing on user experience through interactive dashboards and data visualization.

The application appears to be designed for professionals to track their career development, goals, and progress over time with visual analytics and an intuitive interface.

## 📸 Screenshots

<details>
  <summary><b>Click to view all screenshots</b></summary>

  <br>

  <details>
    <summary><b>🏠 Homepage</b></summary>
    <img width="1919" height="981" alt="Homepage Screenshot" src="https://github.com/user-attachments/assets/83698d2e-30c6-4418-b4fc-f6ebead8d58f" />
  </details>

  <details>
    <summary><b>📊 Dashboard</b></summary>
    <img width="1599" height="1086" alt="Dashboard Screenshot" src="https://github.com/user-attachments/assets/6e6a916f-2d2a-403e-b647-29e3f0ab7faf" />
  </details>

  <details>
    <summary><b>⏱️ Timr</b></summary>
    <img width="1595" height="971" alt="Timr Screenshot" src="https://github.com/user-attachments/assets/2337d05e-518b-4f13-98c6-ee3537eaeb3a" />
  </details>

  <details>
    <summary><b>🗓️ Planner</b></summary>
    <img width="1600" height="1172" alt="Planner Screenshot" src="https://github.com/user-attachments/assets/5f786620-f3a2-479e-9bee-cfb0ac35db1e" />
  </details>

  <details>
    <summary><b>💼 Jobs Tracker</b></summary>
    <img width="1599" height="1117" alt="Jobs Tracker Screenshot" src="https://github.com/user-attachments/assets/92a7af97-7015-4264-944a-713a13829826" />
  </details>

</details>

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 19+ with Vite as the build tool and development server
- **Styling**: Tailwind CSS for utility-first styling with custom CSS variables for theming
- **UI Components**: Custom dark theme with neon blue (#00f3ff) and purple (#9d4edd) accents
- **Icons**: Font Awesome for consistent iconography
- **Build System**: Vite configured for hot module replacement and optimized production builds
- **Development Server**: Configured to run on port 5000 with proxy to backend API on port 3001

### Backend Architecture
- **Framework**: Express.js server providing REST API endpoints
- **Database**: MongoDB support with graceful fallback to in-memory storage when no connection string is provided
- **Authentication**: JWT-based authentication with bcrypt password hashing and role-based access control
- **API Endpoints**: RESTful API for user data, timer sessions, tasks, jobs, dashboard metrics, and admin functionality
- **Admin Features**: Comprehensive admin panel with user management, system statistics, and administrative controls
- **Development Server**: Runs on port 3001 with CORS enabled for frontend communication

### Data Visualization
- **Charts**: Chart.js with React integration via react-chartjs-2 for displaying career progress metrics
- **Interactive Elements**: SortableJS for drag-and-drop functionality, likely for organizing goals or tasks

### User Interface Design
- **Theme**: Dark mode interface with glassmorphism effects (backdrop blur, semi-transparent backgrounds)
- **Layout**: Sidebar navigation pattern with card-based content organization
- **Responsive Design**: Mobile-first approach with viewport-aware styling
- **Animations**: CSS transitions and hover effects for enhanced user experience

### Development Environment
- **Server Configuration**: Vite development server configured to run on port 5000
- **Hot Reload**: Automatic refresh during development for improved developer experience

## External Dependencies

### Core Libraries
- **React Ecosystem**: React 19.1.1 and React DOM for component-based UI development
- **Build Tools**: Vite 7.1.4 with React plugin for fast development and building

### UI and Styling
- **Tailwind CSS**: Utility-first CSS framework loaded via CDN
- **Font Awesome**: Icon library (both CDN and npm package versions)
- **Custom CSS**: Theme variables and component styling for consistent branding

### Data Visualization and Interaction
- **Chart.js 4.5.0**: Comprehensive charting library for progress visualization
- **react-chartjs-2 5.3.0**: React wrapper for Chart.js integration
- **SortableJS 1.15.6**: Drag-and-drop functionality for interactive lists

### Content Delivery
- **CDN Dependencies**: Tailwind CSS and Font Awesome loaded from external CDNs for faster initial load times
- **Static Assets**: Vite development server for serving application assets

The architecture prioritizes user experience with smooth animations, responsive design, and rich data visualization capabilities while maintaining a modern, professional aesthetic suitable for career tracking applications.

## Admin System

### Admin User Creation
- **Default Admin**: Any user registering with `admin@launchlog.com` automatically receives admin privileges
- **Role-Based Access**: Users have either 'admin' or 'user' roles stored in the database
- **JWT Integration**: Admin role is included in authentication tokens for secure access control

### Admin Features
- **User Management Dashboard**: Complete overview of all registered users with creation dates and roles
- **System Statistics**: Real-time metrics showing total users, focus sessions, tasks, and system status
- **User Administration**: Ability to view user details and delete non-admin users
- **Protected Routes**: Admin-only API endpoints secured with middleware authentication
- **Admin Panel Access**: Dedicated admin section in the sidebar navigation (visible only to admin users)

### Admin Security
- **Middleware Protection**: All admin routes protected by authentication and role verification middleware
- **Safe User Display**: User passwords are never exposed in admin user listings
- **Admin Preservation**: Admin users cannot be deleted through the admin interface for security
