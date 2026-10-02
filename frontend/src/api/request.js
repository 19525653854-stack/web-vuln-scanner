// 统一的请求封装。所有页面都从这里发请求，不在组件里各写各的 axios。
// 为什么必须收口：令牌要统一挂、401 要统一处理。散着写的话，迟早有页面漏挂令牌，
// 表现就是"这个页面莫名其妙要重新登录"
import axios from 'axios'
import { ElMessage } from 'element-plus'

const request = axios.create({
  // 走 vite 的代理前缀，前端代码里不出现后端地址
  baseURL: '/api',
  // 超时给到一分钟：扫描任务的创建接口偶尔要等调度器响应
  timeout: 60000
})

request.interceptors.request.use((config) => {
  const accessToken = localStorage.getItem('access_token')
  if (accessToken) {
    config.headers.Authorization = 'Bearer ' + accessToken
  }
  return config
})

request.interceptors.response.use(
  (response) => response.data,
  (error) => {
    // 后端把错误统一成 {code, msg}，优先把那句人话提示拿出来给用户看
    const errorData = error.response?.data || {}
    const errorMessage = errorData.msg || errorData.detail || '请求失败，确认后端服务是否已启动'

    if (error.response?.status === 401) {
      // 令牌过期或被清掉了，清干净再回登录页，不然会来回弹提示
      localStorage.removeItem('access_token')
      localStorage.removeItem('username')
      ElMessage.error(errorMessage)
      window.location.href = '/login'
      return Promise.reject(error)
    }

    ElMessage.error(errorMessage)
    return Promise.reject(error)
  }
)

export default request
