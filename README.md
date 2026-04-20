# derp-scout

用 Python 从 FOFA 搜索疑似 Tailscale DERP 节点，做基础可用性探测，然后生成可直接复制到 Tailscale tailnet policy 里的 `derpMap` 片段。

## 功能

- 调 FOFA API 查询候选节点
- 或读取你手工导出的 FOFA JSON / JSONL 结果
- 并发探测 `TCP 443`
- 校验 `TLS` 握手和证书可验证性
- 做 HTTPS 探针，默认依次尝试 `/derp/probe` 和 `/`
- 可选做 `UDP 3478` STUN 探测
- 生成：
  - 探测结果 JSON
  - 可复制粘贴的 `derpMap` 片段

## 依赖

- Python 3.9+
- FOFA API 凭据

脚本只使用标准库，没有第三方依赖。

## 支持的输入方式

- `FOFA API`
  - 适合你有额度时直接查询
- `本地导出文件`
  - 适合你现在这种没有 API 额度、手工从网页版导出结果的场景

## 环境变量

```powershell
$env:FOFA_EMAIL="you@example.com"
$env:FOFA_KEY="your_fofa_api_key"
```

## 最小示例

```powershell
python .\fofa_derp_acl.py `
  --query 'body="Tailscale" && body="DERP server" && country="HK"' `
  --size 30 `
  --region-id 900 `
  --region-code "cn-derp" `
  --region-name "CN DERP" `
  --max-latency-ms 100 `
  --json-out .\report.json `
  --policy-out .\derpmap.json
```

如果你的环境里不是 `python`，把命令替换成实际 Python 启动方式，例如 `python3`。

## 读取你手工导出的 JSONL

fofa给的这种格式可以直接用，一行一个 JSON 对象，例如：

```json
{"city":"Hong Kong","country":"CN","domain":"","host":"https://1.1.1.1:10443","ip":"1.1.1.1,"link":"https://1.1.1.1:10443","org":"DMIT Cloud Services","port":"10443","protocol":"https","title":""}
{"city":"Hong Kong","country":"CN","domain":"","host":"2.2.2.2","ip":"2.2.2.2","link":"http://2.2.2.2","org":"Alibaba US Technology Co., Ltd.","port":"80","protocol":"http","title":""}
```

保存成 `fofa_export.jsonl` 后直接跑：

```powershell
python .\fofa_derp_acl.py `
  --input-file .\fofa_export.jsonl `
  --region-id 900 `
  --region-code "hk-derp" `
  --region-name "HK DERP" `
  --max-latency-ms 100 `
  --json-out .\report.json `
  --policy-out .\derpmap.json
```

脚本也支持标准 JSON 数组文件。

## 更严格一点的筛选

```powershell
python .\fofa_derp_acl.py `
  --query 'body="Tailscale" && body="DERP server" && country="HK"' `
  --max-latency-ms 100 `
  --require-http-hint `
  --require-stun `
  --omit-default-regions `
  --json-out .\report.json `
  --policy-out .\derpmap.json
```

## 常用参数

- `--query`
  - FOFA 查询语句，默认是 `body="Tailscale" && body="DERP server" && country="HK"`
- `--input-file`
  - 从本地 JSON / JSONL 文件读取候选，不调用 FOFA API
- `--size`
  - 拉多少条 FOFA 结果
- `--timeout`
  - 每个探针的超时秒数
- `--max-latency-ms`
  - 只保留延迟不高于这个阈值的节点，默认 `100`
- `--workers`
  - 并发数
- `--require-http-hint`
  - 只有 HTTP 返回里带明显 DERP 特征时才纳入最终结果
- `--require-stun`
  - 只有 UDP 3478 STUN 成功时才纳入最终结果
- `--allow-ip-hostname`
  - 允许把 IP 字面量直接写进 `HostName`
  - 默认关闭，因为这类节点常常会卡在 TLS 证书校验上，不适合“直接复制粘贴”
- `--omit-default-regions`
  - 生成 `OmitDefaultRegions: true`
- `--lowercase-keys`
  - 把输出里的键名改成小写风格，兼容部分策略示例

## 输出说明

终端里会输出每个候选的探测结果摘要，例如：

- `PASS`
  - 可以直接进入 `derpMap`
- `SKIP`
  - 不建议直接写入策略，原因会显示在下一行

生成的 `derpMap` 片段示例：

```json
{
  "derpMap": {
    "OmitDefaultRegions": false,
    "Regions": {
      "900": {
        "RegionID": 900,
        "RegionCode": "cn-derp",
        "RegionName": "CN DERP",
        "Nodes": [
          {
            "Name": "900a",
            "RegionID": 900,
            "HostName": "example.com",
            "DERPPort": 443,
            "IPv4": "203.0.113.10",
            "STUNPort": 3478
          }
        ]
      }
    }
  }
}
```

## 复制到 Tailscale 的位置

把生成的 `derpMap` 合并到你的 tailnet policy file 顶层对象里。

## 注意

- 这个工具做的是“工程上够用”的可达性筛选，不是完整的 Tailscale 协议级验收。
- 默认会要求：
  - `TCP 443` 能连
  - `TLS` 证书校验通过
  - `HTTPS` 探针有响应
  - 延迟不高于 `100ms`
- 如果你导出的结果里是 `http://...:80` 这种资产，脚本会照样探测，但大概率会因为不是有效 DERP HTTPS 节点而被过滤掉。
- 如果 FOFA 返回的是 IP 而不是域名，大概率会因为证书校验不通过被过滤掉，这通常是符合预期的。
- Tailscale 官方文档确认可以在 tailnet policy 中使用 `derpMap` 自定义 DERP；官方默认 DERP map 可从：
  - [Tailscale DERP servers docs](https://tailscale.com/docs/reference/derp-servers)
  - [Default DERP map](https://controlplane.tailscale.com/derpmap/default)

## 建议的下一步

如果你希望，我还可以继续帮你补两件事：

1. 加一个 `--country/--city` 之类的地理过滤参数
2. 加一个“把多个可用节点按国家/城市自动拆成多个 region”的模式
