local cjson = require "cjson"
local server_section = arg[1]
local proto = arg[2]
local local_port = arg[3] or "0"

-- 辅助函数：检测文件是否存在
function file_exists(name)
   local f = io.open(name, "r")
   if f ~= nil then io.close(f) return true else return false end
end

-- 获取数据库中的节点配置
local ssrindext = io.popen("dbus get ssconf_basic_json_" .. server_section)
local servertmp = ssrindext:read("*all")
local server = cjson.decode(servertmp)

-- 逻辑判断核心
-- 1. 优先检测 /usr/bin/trojan
-- 2. 其次检测 /usr/bin/xray
-- 3. 都没有，默认为 trojan 模式 (Scenario 3)
local use_xray = false
if file_exists("/usr/bin/trojan") then
    use_xray = false
elseif file_exists("/usr/bin/xray") then
    use_xray = true
else
    use_xray = false -- 默认回退到原版逻辑
end

-- 构建配置结构
if use_xray then
    -- ============================================================
    -- 模式 A: 生成 Xray 格式配置 (因为检测到了 xray 且没有 trojan)
    -- ============================================================
    trojan = {
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
                    }
                }
            },
            streamSettings = {
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
            }
        }
    }
else
    -- ============================================================
    -- 模式 B: 生成原版 Trojan 格式配置 (Scenario 1 & 3)
    -- ============================================================
    trojan = {
    	log_level = 99,
    	run_type = proto,
    	local_addr = "0.0.0.0",
    	local_port = tonumber(local_port),
    	remote_addr = server.server,
    	remote_port = tonumber(server.server_port),
    	udp_timeout = 60,
    	-- 传入连接
    	password = {server.password},
    	-- 传出连接
    	ssl = {
    		verify = (server.insecure == "0") and true or false,
    		verify_hostname = (server.tls == "1") and true or false,
    		cert = "/usr/bin/cacert.pem",
    		cipher = "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
    		cipher_tls13 = "TLS_CHACHA20_POLY1305_SHA256",
    		sni = server.tls_host,
    		alpn = {"h2", "http/1.1"},
    		curve = "",
    		reuse_session = true,
    		session_ticket = false,
    		},
    		tcp = {
    			no_delay = true,
    			keep_alive = true,
    			reuse_port = true,
    			fast_open = (server.fast_open == "1") and true or false,
    			fast_open_qlen = 20
    		}
    }
end
-- 输出 JSON
print(cjson.encode(trojan))


