<template>
  <el-container class="layout-root">
    <el-aside width="210px" class="layout-aside">
      <div class="layout-logo">智能Web漏洞扫描系统</div>
      <el-menu :default-active="activeMenu" router class="layout-menu">
        <!-- 菜单以后会随功能补齐：目标管理、任务列表各占一项 -->
        <el-menu-item index="/settings">模型配置</el-menu-item>
        <el-menu-item index="/vulnerabilities">漏洞列表</el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="layout-header">
        <span class="layout-title">{{ pageTitle }}</span>
        <span class="layout-user">
          <span class="layout-username">{{ username }}</span>
          <el-button link type="primary" @click="layout_run_logout">退出登录</el-button>
        </span>
      </el-header>
      <el-main class="layout-main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()

const activeMenu = computed(() => route.path)
const pageTitle = computed(() => route.meta?.title || '智能Web漏洞扫描系统')
const username = computed(() => localStorage.getItem('username') || '未登录')

// 退出只清本地令牌。服务端是无状态令牌，没有会话可以注销，清掉就等于退出
function layout_run_logout() {
  localStorage.removeItem('access_token')
  localStorage.removeItem('username')
  router.push('/login')
}
</script>

<style scoped>
.layout-root {
  height: 100vh;
}

.layout-aside {
  background: #ffffff;
  border-right: 1px solid #e4e7ed;
}

.layout-logo {
  height: 56px;
  line-height: 56px;
  padding: 0 16px;
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  border-bottom: 1px solid #e4e7ed;
}

.layout-menu {
  border-right: none;
}

.layout-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #ffffff;
  border-bottom: 1px solid #e4e7ed;
}

.layout-title {
  font-size: 15px;
  font-weight: 600;
  color: #303133;
}

.layout-user {
  display: flex;
  align-items: center;
  gap: 12px;
}

.layout-username {
  font-size: 13px;
  color: #606266;
}

.layout-main {
  background: #f0f2f5;
}
</style>
