<template>
  <div class="target-page">
    <el-card shadow="never">
      <template #header>录入扫描目标</template>
      <el-form :model="targetForm" label-width="100px" class="target-form">
        <el-form-item label="目标名称">
          <el-input v-model="targetForm.target_name" placeholder="例如 内网门户系统" style="max-width: 320px" />
        </el-form-item>
        <el-form-item label="目标地址">
          <el-input
            v-model="targetForm.target_url"
            placeholder="http:// 或 https:// 开头，例如 http://192.168.1.10/"
          />
        </el-form-item>
        <el-form-item label="授权确认">
          <el-checkbox v-model="targetForm.authorized">
            我确认已获得对该目标进行安全测试的授权
          </el-checkbox>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="submitLoading" @click="target_run_add">录入目标</el-button>
          <span class="form-note">不勾授权也能录入，但没确认授权的目标开不了扫描任务</span>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never" class="target-list-card">
      <template #header>已录入的目标</template>
      <el-table v-loading="listLoading" :data="targetList" size="small">
        <el-table-column prop="id" label="编号" width="70" />
        <el-table-column prop="target_name" label="目标名称" width="160" />
        <el-table-column prop="target_url" label="目标地址" min-width="220" show-overflow-tooltip />
        <el-table-column label="授权" width="90">
          <template #default="scope">
            <el-tag v-if="scope.row.authorized" type="success" size="small">已确认</el-tag>
            <el-tag v-else type="info" size="small">未确认</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="authorized_at" label="授权确认时间" width="150">
          <template #default="scope">{{ scope.row.authorized_at || '—' }}</template>
        </el-table-column>
        <el-table-column prop="created_at" label="录入时间" width="150" />
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="scope">
            <el-button
              link
              type="primary"
              :disabled="!scope.row.authorized"
              @click="target_run_create_job(scope.row)"
            >
              开扫
            </el-button>
            <el-tooltip v-if="!scope.row.authorized" content="没确认授权的目标不能开扫" placement="top">
              <span class="disabled-hint">?</span>
            </el-tooltip>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" class="target-list-card">
      <template #header>
        <div class="card-header-row">
          <span>最近的任务</span>
          <el-button link type="primary" @click="job_load_list">刷新</el-button>
        </div>
      </template>
      <el-table v-loading="jobLoading" :data="jobList" size="small">
        <el-table-column prop="job_id" label="任务号" width="80" />
        <el-table-column prop="target_name" label="目标" min-width="150" show-overflow-tooltip />
        <el-table-column label="状态" width="100">
          <template #default="scope">
            <el-tag :type="job_parse_status_tag(scope.row.status)" size="small">
              {{ job_parse_status_label(scope.row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="轮次" width="100">
          <template #default="scope">{{ scope.row.current_round }} / {{ scope.row.total_round || '—' }}</template>
        </el-table-column>
        <el-table-column prop="finding_count" label="漏洞" width="80" />
        <el-table-column prop="started_at" label="开始时间" width="160" />
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="scope">
            <el-button link type="primary" @click="job_open_detail(scope.row)">查看详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'

import request from '../api/request'

const router = useRouter()

const targetList = ref([])
const jobList = ref([])
const listLoading = ref(false)
const jobLoading = ref(false)
const submitLoading = ref(false)

const targetForm = ref({ target_name: '', target_url: '', authorized: false })

// 地址得先过一遍前端校验，省得明显不合规的串白白走一趟后端
function target_check_url(rawUrl) {
  const trimmedUrl = (rawUrl || '').trim()
  return trimmedUrl.startsWith('http://') || trimmedUrl.startsWith('https://')
}

async function target_load_list() {
  listLoading.value = true
  try {
    const listResult = await request.get('/target/list')
    targetList.value = listResult.data || []
  } finally {
    listLoading.value = false
  }
}

async function target_run_add() {
  if (!targetForm.value.target_name) {
    ElMessage.warning('先给目标起个名字')
    return
  }
  if (!target_check_url(targetForm.value.target_url)) {
    ElMessage.warning('地址得带 http:// 或 https:// 开头')
    return
  }
  if (!targetForm.value.authorized) {
    ElMessage.warning('不勾授权确认也可以录入，但这个目标开不了扫描任务')
  }

  submitLoading.value = true
  try {
    const addResult = await request.post('/target/add', targetForm.value)
    if (addResult.code === 0) {
      ElMessage.success('目标已录入')
      targetForm.value.target_name = ''
      targetForm.value.target_url = ''
      targetForm.value.authorized = false
      await target_load_list()
    } else {
      ElMessage.error(addResult.msg)
    }
  } finally {
    submitLoading.value = false
  }
}

// 开扫成功后直接跳到这个任务的详情页，进度在那里实时看
async function target_run_create_job(targetRow) {
  try {
    const createResult = await request.post('/job/create', { target_id: targetRow.id })
    if (createResult.code !== 0) {
      ElMessage.error(createResult.msg)
      return
    }
    ElMessage.success('任务已开始')
    router.push(`/job/${createResult.data.job_id}`)
  } catch (createError) {
    // 拦截器已经弹过提示了，这里不用再弹一遍
  }
}

function job_parse_status_label(statusValue) {
  return { pending: '排队中', running: '执行中', done: '已完成', failed: '已失败' }[statusValue] || statusValue
}

function job_parse_status_tag(statusValue) {
  return { pending: 'info', running: 'warning', done: 'success', failed: 'danger' }[statusValue] || 'info'
}

async function job_load_list() {
  jobLoading.value = true
  try {
    const jobResult = await request.get('/job/list', { params: { page_size: 20 } })
    jobList.value = jobResult.data?.items || []
  } finally {
    jobLoading.value = false
  }
}

function job_open_detail(jobRow) {
  router.push(`/job/${jobRow.job_id}`)
}

onMounted(async () => {
  await Promise.all([target_load_list(), job_load_list()])
})
</script>

<style scoped>
.target-page {
  max-width: 1240px;
}

.target-form {
  max-width: 720px;
}

.form-note {
  margin-left: 12px;
  font-size: 12px;
  color: #909399;
}

.target-list-card {
  margin-top: 16px;
}

.card-header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.disabled-hint {
  margin-left: 4px;
  font-size: 12px;
  color: #c0c4cc;
  cursor: help;
}
</style>
