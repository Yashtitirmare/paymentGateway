import axios from 'axios'

// Create an axios instance with default config
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL + '/api',
  headers: {
    'Content-Type': 'application/json'
  }
})

// Flag to prevent multiple refresh token requests
let isRefreshing = false
// Store pending requests that should be retried after token refresh
let failedQueue = []

// Process the queue of failed requests
const processQueue = (error, token = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error)
    } else {
      prom.resolve(token)
    }
  })

  failedQueue = []
}

// Add a request interceptor
api.interceptors.request.use(
  (config) => {
    // Get token from localStorage
    const token = localStorage.getItem('token')

    // If token exists, add it to the request header
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }

    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Add a response interceptor
api.interceptors.response.use(
  (response) => {
    return response
  },
  async (error) => {
    const originalRequest = error.config

    // If the error is due to an expired token (401) and we haven't tried to refresh yet
    if (error.response?.status === 401 && !originalRequest._retry && localStorage.getItem('token')) {
      console.log('Received 401 error. Token might be expired. URL:', originalRequest.url)

      if (isRefreshing) {
        console.log('Token refresh already in progress. Adding request to queue.')
        // If we're already refreshing, add this request to the queue
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        })
          .then(token => {
            console.log('Queue processed. Retrying request with new token.')
            originalRequest.headers['Authorization'] = `Bearer ${token}`
            return axios(originalRequest)
          })
          .catch(err => {
            console.error('Failed to process queued request:', err)
            return Promise.reject(err)
          })
      }

      originalRequest._retry = true
      isRefreshing = true

      try {
        console.log('Attempting to refresh token...')
        // Try to refresh the token
        const response = await axios.get('/auth/refresh-token', {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          },
          // Prevent this request from triggering another refresh
          _retry: true
        })

        if (response.data.success) {
          console.log('Token refresh successful!')
          // Update token in localStorage
          localStorage.setItem('token', response.data.token)
          // Update user data if needed
          localStorage.setItem('user', JSON.stringify(response.data.user))

          // Update axios default headers
          axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`

          // Process the queue with the new token
          processQueue(null, response.data.token)

          // Retry the original request with the new token
          originalRequest.headers['Authorization'] = `Bearer ${response.data.token}`
          console.log('Retrying original request with new token...')
          return axios(originalRequest)
        } else {
          console.error('Token refresh failed: Server returned unsuccessful response')
          // If refresh failed, redirect to login
          localStorage.removeItem('token')
          localStorage.removeItem('user')
          localStorage.removeItem('sessionExpiry')
          window.location.href = '/login'

          return Promise.reject(error)
        }
      } catch (refreshError) {
        console.error('Token refresh request failed:', refreshError)
        // If refresh request fails, clear auth data and redirect to login
        processQueue(refreshError, null)
        localStorage.removeItem('token')
        localStorage.removeItem('user')
        localStorage.removeItem('sessionExpiry')
        window.location.href = '/login'

        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }

    console.error('API Error:', error.response?.data || error.message)
    return Promise.reject(error)
  }
)

export default api
