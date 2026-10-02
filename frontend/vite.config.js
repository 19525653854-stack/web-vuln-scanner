// 开发期把 /api 前缀代理到后端。
// 为什么这么做：前端代码里就只写相对路径 /api/xxx，不用把后端地址写死在各处；
// 换端口、换机器部署时只改这一处
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    // 必须写死 127.0.0.1，不能留默认的 localhost。
    // 2026-10-02 踩过：默认值在 Windows 上会解析成 IPv6 的 ::1，服务确实起来了，
    // 但 start.bat 和浏览器打开的是 127.0.0.1，两边对不上就是一片连接被拒
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        // 后端路由本身没有 /api 前缀，转发时去掉，不然会全打到 404 上
        rewrite: (path) => path.replace(/^\/api/, '')
      }
    }
  }
})
