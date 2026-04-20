# derp-scout

`derp-scout` 用于从 FOFA 查询结果或手工导出的 JSON/JSONL 数据中筛选候选 Tailscale DERP 节点，探测可用性与延迟，并生成可直接粘贴到 Tailscale tailnet policy 中的 `derpMap` 片段。

## 它做什么

- 支持两种输入源
  - `FOFA API`
  - `本地导出文件`（JSON 或 JSONL）
- 对候选节点执行基础探测
  - `TCP 443`
  - `TLS` 握手和证书校验
  - `HTTPS` 探针，默认尝试 `/derp/probe`，失败后回退到 `/`
  - 可选 `UDP 3478` STUN 探测
- 按条件筛选
  - 默认只保留延迟 `<= 100ms` 的节点
- 生成两类输出
  - 完整探测报告 JSON
  - 可直接复制到 Tailscale policy 的 `derpMap`

## 重要说明

每个筛选通过的第三方 DERP 节点都会生成独立的 region。

也就是：

- 第 1 个节点 `RegionID = 900`
- 第 2 个节点 `RegionID = 901`
- 第 3 个节点 `RegionID = 902`

这样不会把互不相关的第三方 DERP 节点错误地放进同一个 region。

## 依赖

- Python 3.9+
- 如果使用 API 模式，需要 FOFA 凭据

脚本只使用 Python 标准库，没有第三方依赖。

## 输入方式

### 1. FOFA API 模式

适合有 FOFA API 额度时直接查询。

环境变量示例：

```powershell
$env:FOFA_EMAIL="you@example.com"
$env:FOFA_KEY="your_fofa_api_key"
```

执行示例：

```powershell
python .\fofa_derp_acl.py `
  --query 'body="Tailscale" && body="DERP server" && country="HK"' `
  --size 30 `
  --region-id 900 `
  --region-code "hk-derp" `
  --region-name "HK DERP" `
  --max-latency-ms 100 `
  --json-out .\report_hk.json `
  --policy-out .\derpmap_hk.json
```

如果你的环境里不是 `python`，请替换成实际的 Python 启动命令。

### 2. 本地文件模式

适合没有 API 额度、从网页版手工导出结果时使用。

支持格式：

- `JSONL`
  - 一行一个 JSON 对象
- `JSON`
  - 顶层是数组

JSONL 示例：

```json
{"city":"Hong Kong","country":"CN","domain":"","host":"https://derp-a.example.com:443","ip":"203.0.113.10","link":"https://derp-a.example.com:443","org":"Example Cloud","port":"443","protocol":"https","title":""}
{"city":"Hong Kong","country":"CN","domain":"","host":"https://derp-b.example.com:443","ip":"203.0.113.11","link":"https://derp-b.example.com:443","org":"Example Hosting","port":"443","protocol":"https","title":""}
```

执行示例：

```powershell
python .\fofa_derp_acl.py `
  --input-file .\fofa_export_hk.jsonl `
  --region-id 900 `
  --region-code "hk-derp" `
  --region-name "HK DERP" `
  --max-latency-ms 100 `
  --json-out .\report_hk.json `
  --policy-out .\derpmap_hk.json
```

## 常用筛选规则

默认筛选条件：

- `TCP 443` 可连
- `TLS` 证书校验通过
- `HTTPS` 探针成功
- 延迟不高于 `100ms`

可选更严格模式：

```powershell
python .\fofa_derp_acl.py `
  --input-file .\fofa_export_hk.jsonl `
  --region-id 900 `
  --region-code "hk-derp" `
  --region-name "HK DERP" `
  --max-latency-ms 100 `
  --require-http-hint `
  --require-stun `
  --omit-default-regions `
  --json-out .\report_hk.json `
  --policy-out .\derpmap_hk.json
```

## 常用参数

- `--input-file`
  - 从本地 JSON / JSONL 文件读取候选，不调用 FOFA API
- `--query`
  - FOFA 查询语句
  - 默认值：`body="Tailscale" && body="DERP server" && country="HK"`
- `--size`
  - FOFA API 每次请求拉取的结果数
- `--timeout`
  - 单个探针超时秒数
- `--workers`
  - 并发探测线程数
- `--max-latency-ms`
  - 只保留延迟不高于该值的节点，默认 `100`
- `--require-http-hint`
  - 只有 HTTP 返回里包含明显 DERP 特征时才纳入最终结果
- `--require-stun`
  - 只有 UDP 3478 STUN 探测成功时才纳入最终结果
- `--allow-ip-hostname`
  - 允许 IP 字面量直接写入 `HostName`
  - 默认关闭，因为这类节点通常会卡在 TLS 证书校验
- `--omit-default-regions`
  - 生成 `OmitDefaultRegions: true`
- `--json-out`
  - 输出完整探测报告
- `--policy-out`
  - 输出 `derpMap` 片段

## 输出文件

### `report_hk.json`

完整探测报告，包含：

- 输入来源
- 探测参数
- 每个候选节点的探测结果
- 最终生成的 policy 片段

### `derpmap_hk.json`

只包含可直接复制到 Tailscale policy 的 `derpMap`。

示例：

```json
{
  "derpMap": {
    "OmitDefaultRegions": false,
    "Regions": {
      "900": {
        "RegionID": 900,
        "RegionCode": "hk-derp-900",
        "RegionName": "HK DERP 900",
        "Nodes": [
          {
            "Name": "900a",
            "RegionID": 900,
            "HostName": "derp-a.example.com",
            "DERPPort": 443,
            "IPv4": "203.0.113.10",
            "STUNPort": 3478
          }
        ]
      },
      "901": {
        "RegionID": 901,
        "RegionCode": "hk-derp-901",
        "RegionName": "HK DERP 901",
        "Nodes": [
          {
            "Name": "901a",
            "RegionID": 901,
            "HostName": "derp-b.example.com",
            "DERPPort": 443,
            "IPv4": "203.0.113.11",
            "STUNPort": 3478
          }
        ]
      }
    }
  }
}
```

## 如何放进 Tailscale policy

把生成的 `derpMap` 合并到 tailnet policy 顶层对象中。

如果你已经有 `derpMap`，请用新生成的内容整体替换原来的 `derpMap` 字段，而不是手工拼接旧节点。

## 注意事项

- 这是工程化筛选工具，不是完整的 Tailscale 协议级兼容性验证工具。
- 如果导出结果里有 `http://...:80` 之类的资产，脚本会读取，但通常会在探测阶段被过滤掉。
- 如果候选记录只有 IP、没有可校验证书的域名，通常也会被过滤掉。
- 第三方 DERP 即使延迟低，也不代表长期稳定或互通质量可靠。

## 参考

- [Tailscale DERP servers docs](https://tailscale.com/docs/reference/derp-servers)
- [Default DERP map](https://controlplane.tailscale.com/derpmap/default)
