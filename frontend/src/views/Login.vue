<template>
  <div class="login-page">
    <div class="login-box">
      <div class="login-title">智能Web漏洞扫描系统</div>
      <div class="login-subtitle">V1.0</div>

      <el-form :model="loginForm" label-position="top" @keyup.enter="login_submit">
        <el-form-item label="用户名">
          <el-input v-model="loginForm.username" placeholder="请输入用户名" />
        </el-form-item>
        <el-form-item label="口令">
          <el-input v-model="loginForm.password" type="password" show-password placeholder="请输入口令" />
        </el-form-item>
        <el-button type="primary" :loading="loginLoading" class="login-button" @click="login_submit">
          登录
        </el-button>
      </el-form>

      <div class="login-note">首次启动会创建默认账号，口令见部署说明，登录后请立即修改</div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'

import request from '../api/request'

const router = useRouter()

// 用户名不预填。预填等于把默认账号写进源码里，评审时看着就像硬编码凭据
const loginForm = ref({ username: '', password: '' })
const loginLoading = ref(false)

// 登录成功后把令牌存本地。路由守卫和请求拦截器都从这一处取，不各存各的
async function login_submit() {
  if (!loginForm.value.username || !loginForm.value.password) {
    ElMessage.warning('用户名和口令都要填')
    return
  }

  loginLoading.value = true
  try {
    const loginResult = await request.post('/auth/login', loginForm.value)
    if (loginResult.code !== 0) {
      ElMessage.error(loginResult.msg || '登录失败')
      return
    }

    localStorage.setItem('access_token', loginResult.data.access_token)
    localStorage.setItem('username', loginForm.value.username)
    ElMessage.success('登录成功')
    router.push('/settings')
  } finally {
    loginLoading.value = false
  }
}
</script>

<style scoped>
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
  background: #f0f2f5;
}

.login-box {
  width: 360px;
  padding: 32px 28px 20px;
  background: #ffffff;
  border-radius: 6px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.08);
}

.login-title {
  font-size: 19px;
  font-weight: 600;
  text-align: center;
  color: #303133;
}

.login-subtitle {
  margin: 4px 0 22px;
  font-size: 12px;
  text-align: center;
  color: #909399;
}

.login-button {
  width: 100%;
}

.login-note {
  margin-top: 16px;
  font-size: 12px;
  line-height: 1.7;
  color: #909399;
}
</style>
