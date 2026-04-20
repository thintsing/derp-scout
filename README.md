# derp-scout
derp-scout 是一个基于 Python 的工具，用于从 FOFA 搜索结果或手工导出的 JSON/JSONL 数据中发现候选 Tailscale DERP 节点，探测其 TLS、HTTPS 可用性和延迟，并生成可直接粘贴到 Tailscale tailnet policy 中的 `derpMap` 配置片段。  工具同时支持 FOFA API 模式和离线文件输入模式，适合在没有 API 额度时继续使用。
