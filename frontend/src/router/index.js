import { createRouter, createWebHistory } from 'vue-router'

import Layout from '../views/Layout.vue'
import Login from '../views/Login.vue'
import Settings from '../views/Settings.vue'

const routes = [
  { path: '/login', name: 'login', component: Login, meta: { title: '登录' } },
  {
    path: '/',
    component: Layout,
    // 默认落在模型配置页。系统没配模型什么都跑不起来，先让人把这一步做掉
    redirect: '/settings',
    children: [
      { path: 'settings', name: 'settings', component: Settings, meta: { title: '模型配置' } }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 没登录就打开任何页面，先赶回登录页。
// 为什么放在路由守卫而不是让接口报 401 再跳：那样页面会先渲染一遍再闪走，很难看
router.beforeEach((to) => {
  const accessToken = localStorage.getItem('access_token')
  if (!accessToken && to.name !== 'login') {
    return { name: 'login' }
  }
  return true
})

export default router
