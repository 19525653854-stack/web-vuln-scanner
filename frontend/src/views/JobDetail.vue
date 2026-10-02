<template>
  <div class="job-page">
    <el-card v-if="loadError" shadow="never">
      <el-empty :description="loadError" />
    </el-card>

    <template v-else-if="detail">
      <el-card shadow="never">
        <div class="job-header">
          <div class="job-title">
            <span class="job-number">任务 #{{ detail.job_id }}</span>
            <el-tag :type="job_parse_status_tag(detail.status)">
              {{ job_parse_status_label(detail.status) }}
            </el-tag>
          </div>
          <div class="job-actions">
            <el-button
              :disabled="detail.finding_count === 0"
              @click="job_open_findings"
            >
              查看该任务的漏洞（{{ detail.finding_count }}）
            </el-button>
            <el-button
              type="primary"
              :disabled="detail.status !== 'done'"
              :loading="reportLoading"
              @click="job_run_generate_report"
            >
              生成并下载报告
            </el-button>
          </div>
        </div>

        <el-descriptions :column="3" border class="job-desc">
          <el-descriptions-item label="目标名称">{{ detail.target_name }}</el-descriptions-item>
          <el-descriptions-item label="目标地址" :span="2">{{ detail.target_url }}</el-descriptions-item>
          <el-descriptions-item label="当前轮次">{{ detail.current_round }}</el-descriptions-item>
          <el-descriptions-item label="开始时间">{{ detail.started_at || '—' }}</el-descriptions-item>
          <el-descriptions-item label="结束时间">{{ detail.finished_at || '—' }}</el-descriptions-item>
        </el-descriptions>

        <el-progress
          v-if="detail.status === 'running' || detail.status === 'pending'"
          class="job-progress"
          :percentage="progressPercent"
          :indeterminate="detail.status === 'pending'"
          status="warning"
        />
      </el-card>

      <el-card v-if="detail.reflection?.conclusion" shadow="never" class="job-card">
        <template #header>反思器复核结论</template>
        <div class="reflection-conclusion">{{ detail.reflection.conclusion }}</div>
        <div class="reflection-count">
          复核 {{ detail.reflection.reviewed_count }} 条，
          确认 {{ detail.reflection.confirmed_count }} 条，
          未通过 {{ detail.reflection.unconfirmed_count }} 条
        </div>
      </el-card>

      <el-card v-if="detail.collaboration?.mode" shadow="never" class="job-card">
        <template #header>双智能体协作</template>
        <div class="collab-line">
          协作模式 {{ detail.collaboration.mode }}，
          角色互换 {{ detail.collaboration.swap_times }} 次
          <template v-if="detail.collaboration.role_swapped">（收尾时由顾问主导）</template>
        </div>
        <div v-if="advisorIssues.length" class="collab-issues">
          顾问提出的问题：
          <ul>
            <li v-for="(issueItem, issueIndex) in advisorIssues" :key="issueIndex">{{ issueItem }}</li>
          </ul>
        </div>
      </el-card>

      <el-card v-if="roundSummaries.length" shadow="never" class="job-card">
        <template #header>逐轮判定</template>
        <el-table :data="roundSummaries" size="small">
          <el-table-column prop="round_index" label="轮次" width="70" />
          <el-table-column prop="tool_name" label="工具" width="130" />
          <el-table-column label="判定" width="100">
            <template #default="scope">
              <el-tag :type="scope.row.verdict?.is_vuln ? 'danger' : 'info'" size="small">
                {{ scope.row.verdict?.is_vuln ? '发现' : '无发现' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="置信度" width="90">
            <template #default="scope">{{ Number(scope.row.verdict?.confidence || 0).toFixed(2) }}</template>
          </el-table-column>
          <el-table-column label="理由" min-width="320" show-overflow-tooltip>
            <template #default="scope">{{ scope.row.verdict?.reason }}</template>
          </el-table-column>
        </el-table>
      </el-card>

      <el-card v-if="taskTreeNodes.length" shadow="never" class="job-card">
        <template #header>测试计划（{{ detail.task_tree.goal }}）</template>
        <div class="task-tree">
          <div v-for="taskNode in taskTreeNodes" :key="taskNode.step_no" class="task-node">
            <el-tag :type="job_parse_node_tag(taskNode.node_status)" size="small">
              {{ job_parse_node_label(taskNode.node_status) }}
            </el-tag>
            <span class="node-name">{{ taskNode.skill_name }} / {{ taskNode.tool_name }}</span>
            <span class="node-reason">{{ taskNode.step_reason }}</span>
            <span v-if="taskNode.node_note" class="node-note">{{ taskNode.node_note }}</span>
          </div>
        </div>
      </el-card>
    </template>

    <el-card v-else shadow="never" v-loading="true" />
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'

import request from '../api/request'

const route = useRoute()
const router = useRouter()
const jobId = Number(route.params.jobId)

const detail = ref(null)
const loadError = ref('')
const reportLoading = ref(false)
let pollTimer = null

const roundSummaries = computed(() => detail.value?.round_summaries || [])
const taskTreeNodes = computed(() => detail.value?.task_tree?.nodes || [])
const advisorIssues = computed(() => detail.value?.collaboration?.advisor_issues || [])

// 执行中进度不好精确算百分比，用"已跑轮次比上计划步数"给个大致感，别假装精确
const progressPercent = computed(() => {
  const plannedSteps = (detail.value?.task_tree?.nodes || []).length
  if (!plannedSteps) {
    return 30
  }
  return Math.min(95, Math.round((detail.value.current_round / (plannedSteps + 2)) * 100))
})

function job_parse_status_label(statusValue) {
  return { pending: '排队中', running: '执行中', done: '已完成', failed: '已失败' }[statusValue] || statusValue
}

function job_parse_status_tag(statusValue) {
  return { pending: 'info', running: 'warning', done: 'success', failed: 'danger' }[statusValue] || 'info'
}

function job_parse_node_label(statusValue) {
  return { pending: '待执行', running: '执行中', done: '已完成', skipped: '已跳过', failed: '失败' }[statusValue] || statusValue
}

function job_parse_node_tag(statusValue) {
  return { pending: 'info', running: 'warning', done: 'success', skipped: 'info', failed: 'danger' }[statusValue] || 'info'
}

function job_is_active(statusValue) {
  return statusValue === 'pending' || statusValue === 'running'
}

async function job_load_detail() {
  try {
    const detailResult = await request.get(`/job/detail/${jobId}`)
    if (detailResult.code !== 0) {
      loadError.value = detailResult.msg || '取任务详情失败'
      job_stop_polling()
      return
    }
    detail.value = detailResult.data
    // 任务一结束就停掉轮询，别白刷
    if (!job_is_active(detailResult.data.status)) {
      job_stop_polling()
    }
  } catch (detailError) {
    loadError.value = '取任务详情失败'
    job_stop_polling()
  }
}

function job_start_polling() {
  if (pollTimer) {
    return
  }
  pollTimer = setInterval(job_load_detail, 3000)
}

function job_stop_polling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

function job_open_findings() {
  // 跳漏洞列表页并把任务筛选带上，点过去就是过滤好的结果
  router.push({ path: '/vulnerabilities', query: { job_id: jobId } })
}

// 报告接口要带令牌，直接开新窗口不带请求头会吃 401，先把 PDF 拉成二进制再触发下载
async function job_run_generate_report() {
  reportLoading.value = true
  try {
    const generateResult = await request.post('/report/generate', { job_id: jobId })
    if (generateResult.code !== 0) {
      ElMessage.error(generateResult.msg)
      return
    }
    const pdfBlob = await request.get(`/report/download/${jobId}`, { responseType: 'blob' })
    const downloadUrl = window.URL.createObjectURL(pdfBlob)
    const downloadLink = document.createElement('a')
    downloadLink.href = downloadUrl
    downloadLink.download = `scan_report_job${jobId}.pdf`
    downloadLink.click()
    window.URL.revokeObjectURL(downloadUrl)
    ElMessage.success(generateResult.msg)
  } finally {
    reportLoading.value = false
  }
}

onMounted(async () => {
  await job_load_detail()
  if (detail.value && job_is_active(detail.value.status)) {
    job_start_polling()
  }
})

onUnmounted(job_stop_polling)
</script>

<style scoped>
.job-page {
  max-width: 1180px;
}

.job-card {
  margin-top: 16px;
}

.job-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}

.job-title {
  display: flex;
  align-items: center;
  gap: 12px;
}

.job-number {
  font-size: 18px;
  font-weight: 600;
  color: #303133;
}

.job-actions {
  display: flex;
  gap: 10px;
}

.job-desc {
  margin-bottom: 12px;
}

.job-progress {
  margin-top: 8px;
}

.reflection-conclusion {
  font-size: 14px;
  line-height: 1.8;
  color: #303133;
}

.reflection-count {
  margin-top: 8px;
  font-size: 12px;
  color: #909399;
}

.collab-line {
  font-size: 13px;
  color: #606266;
}

.collab-issues {
  margin-top: 10px;
  font-size: 13px;
  color: #606266;
}

.collab-issues ul {
  margin: 6px 0 0;
  padding-left: 18px;
  line-height: 1.9;
}

.task-tree {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.task-node {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 13px;
}

.node-name {
  min-width: 200px;
  color: #303133;
}

.node-reason {
  flex: 1;
  color: #606266;
}

.node-note {
  color: #909399;
}
</style>
