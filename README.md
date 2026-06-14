# CF Request Analytics Panel

Cloudflare 多账号请求分析面板，支持按账号、区域、域名、子域名、Worker 服务名和时间范围筛选数据，查看 HTTP 请求、Workers / Pages 用量、流量趋势、Top IP / Top Host，并通过 Workers AI 分析服务入口的异常风险。

[在线 Demo](https://cf-analytics-demo.cce.de5.net/)

## 功能

- 多账号请求汇总与单账号查看
- 按区域、域名、子域名、Worker 服务名筛选
- HTTP 请求数、边缘响应流量、Top IP、Top Host
- Workers / Pages 免费额度进度
- 可输出兼容[edgetunnel](https://github.com/cmliu/edgetunnel)的统计API,格式`/usage.json`
- 1h / 6h / 12h / 24h / 3天 / 7天 趋势图
- Worker 服务名项目级请求统计
- AI 分析当前筛选范围的异常风险
- 管理员登录与后台账号管理
- 未登录隐私展示控制

## 目录结构

```txt
src/worker.js              # 核心业务逻辑
functions/[[path]].js      # Cloudflare Pages Functions 入口
public/.gitkeep            # Pages 静态输出目录占位
wrangler.example.toml      # Wrangler 配置示例，不会被 Pages 自动读取
```

## 配置

| 类型 | 名称 | 必填 | 说明 |
| --- | --- | --- | --- |
| KV 绑定 | `KV` | 是 | 保存账号配置和隐私设置 |
| Workers AI 绑定 | `AI` | 否 | 调用 Workers AI 进行风险分析（可选，不绑定仍可使用数据查看功能） |
| 环境变量 | `ADMIN_USER` | 否 | 管理员用户名，默认 `admin` |
| 环境变量 | `ADMIN_PASSWORD` | 是 | 管理员密码 |
| 环境变量 | `CRON_SECRET` | 否 | URL触发采集认证密钥 |
| 环境变量 | `AI_MODEL` | 否 | AI 模型名称，默认 `@cf/openai/gpt-oss-20b` |

## Cloudflare Pages 部署

### 1. Fork 仓库

先在 GitHub 上 Fork 本仓库到自己的账号下，然后在 Cloudflare Dashboard 中进入：

```txt
存储和数据库-> Workers KV -> Create Instance/创建实例 -> 命名空间名称：cf-request-analytics-panel -> 创建
```
命名空间名称你可以设置直接喜欢的，但要在接下来的步骤里，选择对应的Workers KV，完成后：

```txt
计算 -> Workers 和 Pages -> 创建应用程序 -> 想要部署 Pages？开始使用 -> 导入现有 Git 存储库 -> 你Fork的仓库
```

### 2. 构建设置

Pages 构建配置建议如下：
| 项目 | 值 |
| --- | --- |
| 项目名称 | `cf-request-analytics-panel` 或自定义 |
| 生产分支 | `main` |
| 框架预设 | None / 无 |
| 构建命令 | 留空 |
| 构建输出目录 | 留空或 `/` |
| 根目录（高级） | 留空 |
| 环境变量（高级） | 留空 |

仓库默认不包含 `wrangler.toml`，避免 Cloudflare Pages 将绑定切换为配置文件管理。请按下方步骤在 Pages Dashboard 中绑定 `KV`、`AI` 和环境变量。

### 3. 绑定 KV

无需等待部署，点击下方`继续处理项目`，确认取消部署，来到项目主页：
```txt
设置 -> 绑定 -> 添加 KV 命名空间 -> 变量名称输入：KV -> KV 命名空间：cf-request-analytics-panel -> 保存
```
如果你在第一步自定义了名称，这里的KV 命名空间选择你自定义的名称

### 4. 绑定 Workers AI（可选）

在 Pages 项目中进入：

```txt
设置 -> 绑定 -> 添加 Workers AI -> 变量名称输入：AI -> 保存
```

此步骤可跳过，不绑定 AI 不影响数据查看功能，仅 AI 分析不可用。



### 5. 设置环境变量

在 Pages 项目中进入：

```txt
设置 -> 变量和机密 -> 类型：文本 -> 变量名称：ADMIN_PASSWORD -> 值：你的后台密码 -> 保存
```

至少设置：

```txt
ADMIN_PASSWORD=你的后台密码
```

可选设置：参考[配置](#配置)

```txt
ADMIN_USER=admin
AI_MODEL=@cf/openai/gpt-oss-20b
```
### 6. 重新部署

上述几个步骤完成保存后：

在 Pages 项目中进入：

```txt
主页标签 -> 部署
```
选择列表第一个，点击右侧的 `⋯` ,选择`重新部署`，等待部署完成

## 使用

1. 打开 Pages 分配的域名。
2. 使用管理员账号登录。
3. 进入后台添加 Cloudflare 账号配置。
4. 填写 Account ID、API Token 和 Zone ID。
5. 返回首页按账号、区域、主机名、服务名和时间范围筛选数据。
6. 点击 AI 分析，查看当前筛选范围的风险判断。

### Account ID、API Token 和 Zone ID 获取

#### 1. API Token

在 Cloudflare Dashboard 中进入：

```txt
右上角头像 -> 配置文件 -> API 令牌 -> 创建令牌 -> 使用模板：阅读分析数据和日志 -> 继续以显示摘要 -> 创建令牌
```
复制`cfut_xxx`开头的`API Token`


#### 2. Account ID
在 Cloudflare Dashboard 中进入：
```txt
计算 -> Workers 和 Pages
```
右侧或者底部，复制`Account ID`

#### 3. Zone ID

此项较为特殊，因为每个`Zone ID`对应一个域名，选择你想加入分析的域名,可以输入多个，每行一个

在 Cloudflare Dashboard 中进入：

```txt
域名 -> 概览 -> 需要加入的域名
```
右侧或者底部，复制`区域 ID`

###保存历史数据3天/7天

后台配置中可以选择多久触发一次采集，默认为 `每日一次`

每次采集会将最近24小时的请求数据存入 KV。随着时间的推移，KV 中积累的历史数据可以支持 3 天、7 天的趋势查看。

由于 CF GraphQL API 限制，单次查询只能获取到过去 24 小时的数据，建议至少每 24 小时采集一次以保证数据连续性。

但是由于Pages没有定时任务，如果你清楚如何使用Worker部署，可以自行使用Worker部署

####Worker配置定时任务
在 Worker 项目中进入：

```txt
设置 -> 触发条件 -> 添加 -> Cron 触发器 -> Cron 表达式 
```

在输入中输入：`0 8 * * *` ，意思是每天定时触发一次采集，请注意修改此项，需要配合项目后台设置的采集间隔

####Pages配置定时任务

采集触发API：

```txt
/api/cron/trigger?key=CRON_SECRET
```

使用任意方式定时访问项目API，你可以建立另一个Worker定时触发，也可能使用其他任何外部服务，只要能访问API

例如用 `cron-job.org` `Uptime Kuma` 等外部服务调用 `https://.../api/cron/trigger?key=CRON_SECRET`

URL中的 `CRON_SECRET` 为变量，参考下方设置方式

在 Pages 项目中进入：

```txt
设置 -> 变量和机密 -> 类型：文本 -> 变量名称：CRON_SECRET -> 值：触发采集的密钥 -> 保存
```



## UsageAPI

本项目提供兼容 `edgetunnel` 的公开用量接口：

```txt
/usage.json
```

返回字段包含：`success`、`pages`、`workers`、`total`、`max`、`resources`、`msg`，并允许跨域读取。



## 隐私展示

- Cloudflare API Token 不会在前端展示。
- Zone ID 不会在前端展示。
- 未登录用户默认隐藏敏感数据。
- 管理员可以在后台调整公开隐私设置。



## 许可证

本项目使用 GPL-3.0 License。
