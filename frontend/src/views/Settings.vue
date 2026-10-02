<template>
  <div class="settings-page">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>模型配置</span>
          <el-tag v-if="activeConfigName" type="success">当前生效：{{ activeConfigName }}</el-tag>
          <el-tag v-else type="info">还没有配置过模型</el-tag>
        </div>
      </template>

      <el-form :model="configForm" label-width="100px">
        <el-form-item label="配置名称">
          <el-input v-model="configForm.config_name" placeholder="例如 智谱GLM" style="max-width: 320px" />
        </el-form-item>

        <el-divider content-position="left">主控模型</el-divider>
        <el-row :gutter="16">
          <el-col :span="8">
            <el-form-item label="厂商">
              <el-select v-model="configForm.main_model_provider" @change="settings_apply_provider_defaults">
                <el-option
                  v-for="providerPreset in providerPresets"
                  :key="providerPreset.provider"
                  :label="providerPreset.label"
                  :value="providerPreset.provider"
                />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="模型">
              <!-- 允许手填：厂商新出的模型不该等前端改代码才能用 -->
              <el-select v-model="configForm.main_model_name" filterable allow-create placeholder="可选可填">
                <el-option
                  v-for="modelName in providerModels"
                  :key="modelName"
                  :label="modelName"
                  :value="modelName"
                />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="超时">
              <el-input-number v-model="configForm.timeout" :min="5" :max="180" />
            </el-form-item>
          </el-col>
        </el-row>

        <el-form-item label="API Key">
          <el-input
            v-model="configForm.main_model_api_key"
            type="password"
            show-password
            placeholder="打码值表示沿用已保存的 Key，想换就直接覆盖"
          />
        </el-form-item>
        <el-form-item label="Base URL">
          <el-input v-model="configForm.main_model_base_url" placeholder="留空则用该厂商的预置地址" />
        </el-form-item>

        <el-divider content-position="left">协作模式</el-divider>
        <el-form-item label="模式">
          <el-radio-group v-model="configForm.collaboration_mode">
            <el-radio value="single">单模型（主控独立完成）</el-radio>
            <el-radio value="dual">双模型（顾问用另一套配置复核）</el-radio>
          </el-radio-group>
        </el-form-item>

        <template v-if="configForm.collaboration_mode === 'dual'">
          <el-row :gutter="16">
            <el-col :span="8">
              <el-form-item label="顾问厂商">
                <el-select v-model="configForm.advisor_model_provider" @change="settings_apply_advisor_defaults">
                  <el-option
                    v-for="providerPreset in providerPresets"
                    :key="providerPreset.provider"
                    :label="providerPreset.label"
                    :value="providerPreset.provider"
                  />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item label="顾问模型">
                <el-select v-model="configForm.advisor_model_name" filterable allow-create placeholder="可选可填">
                  <el-option
                    v-for="modelName in advisorModels"
                    :key="modelName"
                    :label="modelName"
                    :value="modelName"
                  />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item label="顾问 Key">
                <el-input v-model="configForm.advisor_model_api_key" type="password" show-password />
              </el-form-item>
            </el-col>
          </el-row>
        </template>

        <el-divider content-position="left">生成参数</el-divider>
        <el-row :gutter="16">
          <el-col :span="8">
            <el-form-item label="温度">
              <el-input-number v-model="configForm.temperature" :min="0" :max="2" :step="0.1" />
            </el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="最大 token">
              <el-input-number v-model="configForm.max_tokens" :min="256" :max="32768" :step="256" />
            </el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="保存即生效">
              <el-switch v-model="configForm.activate" />
            </el-form-item>
          </el-col>
        </el-row>

        <el-form-item>
          <el-button :loading="testLoading" @click="settings_run_connection_test">测试连通性</el-button>
          <el-button type="primary" :loading="saveLoading" @click="settings_run_save">保存配置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="settings-list-card">
      <template #header>已保存的配置</template>
      <el-table :data="configList" size="small">
        <el-table-column prop="config_name" label="配置名称" />
        <el-table-column prop="main_model_provider" label="厂商" width="110" />
        <el-table-column prop="main_model_name" label="模型" width="170" />
        <el-table-column label="Key" width="150">
          <template #default="scope">{{ scope.row.main_model_api_key || '未填' }}</template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="scope">
            <el-tag v-if="scope.row.is_active" type="success">生效中</el-tag>
            <el-button v-else link type="primary" @click="settings_run_activate(scope.row)">启用</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'

import request from '../api/request'

const providerPresets = ref([])
const providerModels = ref([])
const advisorModels = ref([])
const configList = ref([])
const activeConfigName = ref('')
const testLoading = ref(false)
const saveLoading = ref(false)

// 表单的初始值。字段名跟后端表结构一一对应，中间不起别名，免得排查时要在两套名字之间对
const configForm = ref({
  config_name: '',
  main_model_provider: 'zhipu',
  main_model_name: '',
  main_model_api_key: '',
  main_model_base_url: '',
  advisor_model_provider: '',
  advisor_model_name: '',
  advisor_model_api_key: '',
  advisor_model_base_url: '',
  collaboration_mode: 'single',
  temperature: 0.3,
  max_tokens: 4096,
  timeout: 60,
  activate: true
})

// 厂商清单从后端取。前端自己写一份的话，后端加了厂商这里就选不到
async function settings_load_presets() {
  const presetResult = await request.get('/config/presets')
  providerPresets.value = presetResult.data || []
}

async function settings_load_models() {
  if (!configForm.value.main_model_provider) {
    providerModels.value = []
    return
  }
  const modelResult = await request.get('/config/models', {
    params: { provider: configForm.value.main_model_provider }
  })
  providerModels.value = modelResult.data || []
}

async function settings_load_advisor_models() {
  if (!configForm.value.advisor_model_provider) {
    advisorModels.value = []
    return
  }
  const modelResult = await request.get('/config/models', {
    params: { provider: configForm.value.advisor_model_provider }
  })
  advisorModels.value = modelResult.data || []
}

// 换厂商时把地址和模型带过去。不带的话用户得自己去翻厂商文档抄地址
async function settings_apply_provider_defaults() {
  await settings_load_models()
  const matchedPreset = providerPresets.value.find(
    (providerPreset) => providerPreset.provider === configForm.value.main_model_provider
  )
  if (!matchedPreset) {
    return
  }
  configForm.value.main_model_base_url = matchedPreset.default_base_url
  configForm.value.main_model_name = matchedPreset.models[0] || ''
}

async function settings_apply_advisor_defaults() {
  await settings_load_advisor_models()
  const matchedPreset = providerPresets.value.find(
    (providerPreset) => providerPreset.provider === configForm.value.advisor_model_provider
  )
  if (!matchedPreset) {
    return
  }
  configForm.value.advisor_model_base_url = matchedPreset.default_base_url
  configForm.value.advisor_model_name = matchedPreset.models[0] || ''
}

// 把后端返回的配置铺到表单上。Key 拿到的是打码值，直接提交就等于"不改动"
function settings_fill_form(configData) {
  Object.keys(configForm.value).forEach((fieldKey) => {
    if (configData[fieldKey] !== undefined && configData[fieldKey] !== null) {
      configForm.value[fieldKey] = configData[fieldKey]
    }
  })
}

async function settings_load_current() {
  const currentResult = await request.get('/config/current')
  if (currentResult.code === 0 && currentResult.data) {
    activeConfigName.value = currentResult.data.config_name
    settings_fill_form(currentResult.data)
  } else {
    activeConfigName.value = ''
  }
}

async function settings_load_list() {
  const listResult = await request.get('/config/list')
  configList.value = listResult.data || []
}

async function settings_run_connection_test() {
  testLoading.value = true
  try {
    const testResult = await request.post('/config/test', {
      main_model_provider: configForm.value.main_model_provider,
      main_model_name: configForm.value.main_model_name,
      main_model_api_key: configForm.value.main_model_api_key,
      main_model_base_url: configForm.value.main_model_base_url
    })
    // 连通性测试失败也是正常结果，用错误提示展示后端给的原话，不要当异常抛
    if (testResult.code === 0) {
      ElMessage.success(testResult.msg)
    } else {
      ElMessage.error(testResult.msg)
    }
  } finally {
    testLoading.value = false
  }
}

async function settings_run_save() {
  if (!configForm.value.config_name) {
    ElMessage.warning('先给这套配置起个名字')
    return
  }
  saveLoading.value = true
  try {
    const saveResult = await request.post('/config/save', configForm.value)
    if (saveResult.code === 0) {
      ElMessage.success(saveResult.msg)
      await settings_load_current()
      await settings_load_list()
    } else {
      ElMessage.error(saveResult.msg)
    }
  } finally {
    saveLoading.value = false
  }
}

// 启用某一套：把它的内容铺进表单再存一次，靠后端的"保存即生效"完成切换
async function settings_run_activate(configRow) {
  settings_fill_form(configRow)
  configForm.value.activate = true
  await settings_run_save()
}

onMounted(async () => {
  await settings_load_presets()
  await settings_load_current()
  await settings_load_list()
  await settings_load_models()
  await settings_load_advisor_models()
})
</script>

<style scoped>
.settings-page {
  max-width: 1080px;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.settings-list-card {
  margin-top: 16px;
}
</style>
