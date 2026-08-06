-- 数据库脱敏 MCP 网关 - 只读账号创建脚本（通用模板）
-- 执行前请替换以下占位符：
--   <GATEWAY_SERVER_IP>  — 网关服务器内网 IP
--   <STRONG_PASSWORD>     — 强随机密码
--   <DATABASE_NAME>       — 数据库名（与 datasource.yaml 中的 database 字段一致）
--   <TABLE_NAME>          — 逐表替换为实际需要授权的表名

CREATE USER 'ai_gateway_ro'@'<GATEWAY_SERVER_IP>' IDENTIFIED BY '<STRONG_PASSWORD>';

-- 逐表授权 SELECT（按你的实际表名修改）
-- 示例：
-- GRANT SELECT ON <DATABASE_NAME>.dws_example_summary TO 'ai_gateway_ro'@'<GATEWAY_SERVER_IP>';
-- GRANT SELECT ON <DATABASE_NAME>.dwd_example_detail TO 'ai_gateway_ro'@'<GATEWAY_SERVER_IP>';
-- GRANT SELECT ON <DATABASE_NAME>.dim_example_dimension TO 'ai_gateway_ro'@'<GATEWAY_SERVER_IP>';

-- 视图需要额外的 SHOW VIEW 权限
-- GRANT SHOW VIEW ON <DATABASE_NAME>.v_example_view TO 'ai_gateway_ro'@'<GATEWAY_SERVER_IP>';

FLUSH PRIVILEGES;
