local cjson = require "cjson"
local server_section = arg[1]
local proto = arg[2]
local local_port = arg[3] or "0"

-- 获取数据库中的节点配置
local ssrindext = io.popen("dbus get ssconf_basic_json_" .. server_section)
local servertmp = ssrindext:read("*all")
local server = cjson.decode(servertmp)

-- 构建 Xray 格式的配置结构
local xray_trojan = {
    log = {
        loglevel = "warning"
    },
    
    -- 【入站连接】
    -- 这里必须使用 dokodemo-door 协议，配合 iptables 实现透明代理
    inbound = {
        port = tonumber(local_port),
        protocol = "dokodemo-door",
        settings = {
            network = "tcp,udp",
            followRedirect = true
        },
        sniffing = {
            enabled = true,
            destOverride = { "http", "tls" }
        }
    },

    -- 【出站连接】
    -- 这里配置 Trojan 协议详情
    outbound = {
        protocol = "trojan",
        settings = {
            servers = {
                {
                    address = server.server,
                    port = tonumber(server.server_port),
                    password = server.password,
                    email = "t@t.tt" -- 随意填写，Xray中Trojan不强校验这个
                }
            }
        },
        streamSettings = {
            network = "tcp", -- Trojan 协议强制基于 TCP
            security = "tls", -- Trojan 协议强制 TLS
            tlsSettings = {
                -- 注意逻辑：原配置 insecure="1" 代表不安全(不验证)，对应 Xray 的 allowInsecure=true
                allowInsecure = (server.insecure == "1") and true or false,
                serverName = server.tls_host -- SNI
            }
        }
    },

    -- 【额外出站】
    -- 必须保留 freedom 出站，用于直连
    outboundDetour = {
        {
            protocol = "freedom",
            tag = "direct",
            settings = { keep = "" }
        }
    }
}

-- 输出 JSON
print(cjson.encode(xray_trojan))
