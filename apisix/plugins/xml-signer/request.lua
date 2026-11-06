--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local core = require("apisix.core")
local runtime_ok, apisix_ngx_client = pcall(require, "resty.apisix.client")

local ipairs = ipairs
local ngx = ngx
local tostring = tostring
local type = type

local _M = {}

local BODY_DIGEST_HEADERS = {
    "Content-MD5",
    "Digest",
    "Content-Digest",
    "Repr-Digest",
}


local function contains(values, expected)
    for _, value in ipairs(values) do
        if value == expected then
            return true
        end
    end
    return false
end


local function normalized_content_type(value)
    if not value then
        return ""
    end
    local normalized = value:match("^%s*([^;]+)")
    return normalized and normalized:gsub("%s+$", ""):lower() or ""
end


local function has_unsupported_charset(value)
    if not value then
        return false, nil
    end

    local parameter_start
    local quoted = false
    local escaped = false
    local validated_charset

    for index = 1, #value + 1 do
        local char = value:sub(index, index)
        if index > #value or (char == ";" and not quoted) then
            if parameter_start then
                local parameter = value:sub(parameter_start, index - 1)
                local name, charset = parameter:match(
                    "^%s*([^=%s]+)%s*=%s*(.-)%s*$")
                if name and name:lower() == "charset" then
                    charset = charset:match("^%s*(.-)%s*$")
                    if charset:sub(1, 1) == '"' and charset:sub(-1) == '"' then
                        charset = charset:sub(2, -2)
                    end
                    charset = charset:lower()
                    if charset ~= "utf-8" and charset ~= "utf8" then
                        return true
                    end
                    validated_charset = "UTF-8"
                end
            end
            parameter_start = index + 1
        elseif char == '"' and not escaped then
            quoted = not quoted
        end

        if char == "\\" and quoted and not escaped then
            escaped = true
        else
            escaped = false
        end
    end
    return false, validated_charset
end


function _M.rewrite(plugin_name, conf, ctx, sign)
    if type(conf) ~= "table" then
        core.log.error(plugin_name, " configuration is missing")
        return 500, {message = "internal_error"}
    end

    if not contains(conf.request.methods, ngx.req.get_method()) then
        return
    end

    local headers = ngx.req.get_headers(0)
    local content_encoding = headers["content-encoding"]
    if content_encoding ~= nil
       and (type(content_encoding) ~= "string"
            or content_encoding:lower():match("^%s*(.-)%s*$") ~= "identity") then
        return 415, {message = "unsupported_media_type"}
    end
    local content_type_header = headers["content-type"]
    if type(content_type_header) ~= "string" then
        return 415, {message = "unsupported_media_type"}
    end
    local content_type = normalized_content_type(content_type_header)
    local accepted = false
    for _, configured_type in ipairs(conf.request.content_types) do
        if configured_type:lower() == content_type then
            accepted = true
            break
        end
    end
    if not accepted then
        return 415, {message = "unsupported_media_type"}
    end
    local unsupported_charset, charset = has_unsupported_charset(content_type_header)
    if unsupported_charset then
        return 415, {message = "unsupported_media_type"}
    end

    if not runtime_ok then
        core.log.error(plugin_name, " requires APISIX-Runtime to limit request body size")
        return 501, {message = "internal_error"}
    end
    local max_body_bytes = conf.request.max_body_bytes
    if ctx and ctx.client_max_body_size and ctx.client_max_body_size > 0
       and ctx.client_max_body_size < max_body_bytes then
        max_body_bytes = ctx.client_max_body_size
    end
    local limit_ok, limit_err = apisix_ngx_client.set_client_max_body_size(
        max_body_bytes)
    if not limit_ok then
        core.log.error(plugin_name, " failed to set client max body size: ", limit_err)
        return 503, {message = "internal_error"}
    end

    local body, body_err, body_err_code = core.request.get_body(
        conf.request.max_body_bytes, ctx)
    if not body then
        core.log.error(plugin_name, " failed to read request body: ", body_err)
        if not body_err then
            return 400, {message = "empty_body"}
        end
        if body_err_code == "too_large" then
            return 413, {message = "body_too_large"}
        end
        return 500, {message = "internal_error"}
    end

    if conf.signature.algorithm == "rsa-sha1" then
        core.log.warn(plugin_name, " is using legacy SHA-1 cryptography")
    end

    if body == "" then
        return 400, {message = "empty_body"}
    end

    local signed, code, detail = sign(body, conf, charset)
    if not signed then
        core.log.error(plugin_name, " rejected request: ", code, ": ", detail)
        local internal_error = not code or code == "credential_error" or code == "signing_error"
        local status = internal_error and 500 or 400
        return status, {message = code or "internal_error"}
    end

    ngx.req.set_body_data(signed)
    if ctx.var and ctx.var._cache then
        ctx.var._cache.http_content_length = nil
    end
    core.request.set_header(ctx, "Content-Length", tostring(#signed))
    core.request.set_header(ctx, "Transfer-Encoding", nil)
    for _, header in ipairs(BODY_DIGEST_HEADERS) do
        core.request.set_header(ctx, header, nil)
    end
end


return _M