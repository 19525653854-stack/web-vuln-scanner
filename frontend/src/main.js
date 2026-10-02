// 应用入口。挂路由、挂 Element Plus。
// 为什么显式换中文语言包：不换的话分页器、日期选择这些组件的提示文字是英文，
// 整个界面看着就是半拉子
import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import 'element-plus/dist/index.css'

import App from './App.vue'
import router from './router'

const app = createApp(App)
app.use(router)
app.use(ElementPlus, { locale: zhCn })
app.mount('#app')
