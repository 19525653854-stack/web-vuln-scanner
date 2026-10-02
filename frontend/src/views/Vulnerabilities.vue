<template>
  <div class="vuln-page">
    <el-row :gutter="16" class="vuln-stats">
      <el-col :span="6">
        <el-card shadow="never">
          <div class="stat-label">高危</div>
          <div class="stat-value stat-high">{{ levelCounts.high }}</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never">
          <div class="stat-label">中危</div>
          <div class="stat-value stat-medium">{{ levelCounts.medium }}</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never">
          <div class="stat-label">低危</div>
          <div class="stat-value stat-low">{{ levelCounts.low }}</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never">
          <div class="stat-label">合计</div>
          <div class="stat-value">{{ totalFindingCount }}</div>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never">
      <div class="vuln-filter">
        <el-select
          v-model="filterForm.job_id"
          placeholder="全部任务"
          clearable
          class="filter-job"
          @change="vuln_run_reload"
        >
          <el-option
            v-for="jobItem in jobList"
            :key="jobItem.job_id"
            :label="vuln_build_job_label(jobItem)"
            :value="jobItem.job_id"
          />
        </el-select>

        <el-select
          v-model="filterForm.vuln_level"
          placeholder="全部等级"
          clearable
          class="filter-level"
          @change="vuln_run_reload"
        >
          <el-option label="高危" value="high" />
          <el-option label="中危" value="medium" />
          <el-option label="低危" value="low" />
        </el-select>

        <el-select
          v-model="filterForm.vuln_type"
          placeholder="全部类型"
          clearable
          class="filter-type"
          @change="vuln_run_reload"
        >
          <el-option
            v-for="typeItem in vulnTypeList"
            :key="typeItem.vuln_type"
            :label="`${typeItem.vuln_type}（${typeItem.count}）`"
            :value="typeItem.vuln_type"
          />
        </el-select>

        <el-button @click="vuln_run_reload">刷新</el-button>
        <el-button
          type="primary"
          :disabled="!filterForm.job_id"
          :loading="reportLoading"
          @click="vuln_run_generate_report"
        >
          生成并下载该任务报告
        </el-button>
      </div>

      <el-table v-loading="tableLoading" :data="findingList" size="small" class="vuln-table">
        <el-table-column prop="finding_id" label="编号" width="70" />
        <el-table-column prop="job_id" label="任务" width="70" />
        <el-table-column prop="vuln_type" label="漏洞类型" width="120" />
        <el-table-column label="等级" width="90">
          <template #default="scope">
            <el-tag :type="vuln_parse_level_tag(scope.row.vuln_level)" size="small">
              {{ vuln_parse_level_label(scope.row.vuln_level) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="置信度" width="90">
          <template #default="scope">{{ Number(scope.row.confidence || 0).toFixed(2) }}</template>
        </el-table-column>
        <el-table-column prop="vuln_url" label="命中地址" min-width="190" show-overflow-tooltip />
        <el-table-column label="修复建议" min-width="230" show-overflow-tooltip>
          <template #default="scope">{{ scope.row.fix_suggestion || '（暂无）' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="80" fixed="right">
          <template #default="scope">
            <el-button link type="primary" @click="vuln_run_show_detail(scope.row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        class="vuln-pager"
        layout="total, prev, pager, next"
        background
        :total="totalCount"
        :current-page="filterForm.page_index"
        :page-size="filterForm.page_size"
        @current-change="vuln_run_change_page"
      />
    </el-card>

    <el-dialog v-model="detailVisible" title="漏洞详情" width="760px">
      <el-descriptions v-if="detailRow" :column="2" border>
        <el-descriptions-item label="编号">{{ detailRow.finding_id }}</el-descriptions-item>
        <el-descriptions-item label="所属任务">第 {{ detailRow.job_id }} 号</el-descriptions-item>
        <el-descriptions-item label="漏洞类型">{{ detailRow.vuln_type }}</el-descriptions-item>
        <el-descriptions-item label="风险等级">{{ vuln_parse_level_label(detailRow.vuln_level) }}</el-descriptions-item>
        <el-descriptions-item label="置信度">{{ Number(detailRow.confidence || 0).toFixed(2) }}</el-descriptions-item>
        <el-descriptions-item label="发现时间">{{ detailRow.created_at }}</el-descriptions-item>
        <el-descriptions-item label="命中地址" :span="2">{{ detailRow.vuln_url }}</el-descriptions-item>
        <el-descriptions-item label="触发载荷" :span="2">
          {{ detailRow.raw_payload || '（这类检测不带载荷）' }}
        </el-descriptions-item>
        <el-descriptions-item label="判定理由" :span="2">{{ detailRow.validate_reason || '（暂无）' }}</el-descriptions-item>
        <el-descriptions-item label="修复建议" :span="2">{{ detailRow.fix_suggestion || '（暂无）' }}</el-descriptions-item>
      </el-descriptions>

      <el-divider content-position="left">证据片段</el-divider>
      <pre class="vuln-evidence">{{ detailRow?.raw_evidence || '（暂无）' }}</pre>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'

import request from '../api/request'

const findingList = ref([])
const jobList = ref([])
const vulnTypeList = ref([])
const totalCount = ref(0)
const levelCounts = ref({ high: 0, medium: 0, low: 0, other: 0 })
const tableLoading = ref(false)
const reportLoading = ref(false)
const detailVisible = ref(false)
const detailRow = ref(null)

const filterForm = ref({
  job_id: null,
  vuln_level: '',
  vuln_type: '',
  page_index: 1,
  page_size: 20
})

const totalFindingCount = computed(
  () => levelCounts.value.high + levelCounts.value.medium + levelCounts.value.low + levelCounts.value.other
)

function vuln_parse_level_label(levelValue) {
  return { high: '高危', medium: '中危', low: '低危' }[levelValue] || '未定级'
}

// 高危红、中危橙、低危灰。这块沿用国内做风险展示的习惯，不套国外那套配色
function vuln_parse_level_tag(levelValue) {
  return { high: 'danger', medium: 'warning', low: 'info' }[levelValue] || 'info'
}

// 下拉里光有任务编号没法用，得把目标名和扫出几条一起带上，才认得出是哪一次扫描
function vuln_build_job_label(jobItem) {
  return `任务 ${jobItem.job_id}　${jobItem.target_name}　漏洞 ${jobItem.finding_count} 条`
}

async function vuln_load_jobs() {
  const jobResult = await request.get('/job/list', { params: { page_size: 50 } })
  jobList.value = jobResult.data?.items || []
}

async function vuln_load_summary() {
  const summaryResult = await request.get('/finding/summary', {
    params: { job_id: filterForm.value.job_id || 0 }
  })
  const summaryData = summaryResult.data || {}
  levelCounts.value = summaryData.level_counts || { high: 0, medium: 0, low: 0, other: 0 }
  vulnTypeList.value = summaryData.vuln_type_list || []
}

async function vuln_load_list() {
  tableLoading.value = true
  try {
    const listResult = await request.get('/finding/list', { params: filterForm.value })
    findingList.value = listResult.data?.items || []
    totalCount.value = listResult.data?.total || 0
  } finally {
    tableLoading.value = false
  }
}

// 换筛选条件时回到第一页。不回去的话，第 3 页上换条件多半会拿到一个空列表
async function vuln_run_reload() {
  filterForm.value.page_index = 1
  await Promise.all([vuln_load_list(), vuln_load_summary()])
}

async function vuln_run_change_page(pageIndex) {
  filterForm.value.page_index = pageIndex
  await vuln_load_list()
}

async function vuln_run_show_detail(findingRow) {
  const detailResult = await request.get(`/finding/detail/${findingRow.finding_id}`)
  detailRow.value = detailResult.data || findingRow
  detailVisible.value = true
}

// 报告接口要带令牌，直接 window.open 一个新窗口是不带请求头的，会吃 401。
// 所以先用请求把 PDF 拉成二进制，再造一个本地链接触发下载
async function vuln_run_generate_report() {
  reportLoading.value = true
  try {
    const generateResult = await request.post('/report/generate', { job_id: filterForm.value.job_id })
    if (generateResult.code !== 0) {
      ElMessage.error(generateResult.msg)
      return
    }

    const pdfBlob = await request.get(`/report/download/${filterForm.value.job_id}`, {
      responseType: 'blob'
    })
    const downloadUrl = window.URL.createObjectURL(pdfBlob)
    const downloadLink = document.createElement('a')
    downloadLink.href = downloadUrl
    downloadLink.download = `scan_report_job${filterForm.value.job_id}.pdf`
    downloadLink.click()
    window.URL.revokeObjectURL(downloadUrl)
    ElMessage.success(generateResult.msg)
  } finally {
    reportLoading.value = false
  }
}

onMounted(async () => {
  await vuln_load_jobs()
  await Promise.all([vuln_load_list(), vuln_load_summary()])
})
</script>

<style scoped>
.vuln-page {
  max-width: 1320px;
}

.vuln-stats {
  margin-bottom: 16px;
}

.stat-label {
  font-size: 13px;
  color: #909399;
}

.stat-value {
  margin-top: 6px;
  font-size: 26px;
  font-weight: 600;
  color: #303133;
}

.stat-high {
  color: #d93025;
}

.stat-medium {
  color: #e6a23c;
}

.stat-low {
  color: #909399;
}

.vuln-filter {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}

.filter-job {
  width: 320px;
}

.filter-level {
  width: 130px;
}

.filter-type {
  width: 180px;
}

.vuln-table {
  margin-top: 12px;
  width: 100%;
}

.vuln-pager {
  margin-top: 14px;
  justify-content: flex-end;
}

.vuln-evidence {
  max-height: 260px;
  overflow: auto;
  padding: 10px;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-all;
  background: #f5f7fa;
  border-radius: 4px;
}
</style>
