#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
use t::APISIX 'no_plan';

no_long_string();
no_shuffle();
no_root_location();

run_tests;

__DATA__

=== TEST 1: sign proxied XML requests and leave other requests untouched
--- config
    location /upstream {
        content_by_lua_block {
            local core = require("apisix.core")
            local xml = require("apisix.plugins.xml-signer.xml")
            local signer = require("apisix.plugins.xml-signer.signer")

            local body = core.request.get_body() or ""
            local signatures = 0
            local doc = xml.parse(body)
            if doc then
                signatures = #xml.find_all(
                    assert(xml.root(doc)), signer.namespaces.ds, "Signature")
                xml.free_document(doc)
            end
            local length = tonumber(ngx.var.http_content_length) or 0
            ngx.say("signatures=", signatures, " length_ok=", length == #body)
        }
    }
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin")
            local core = require("apisix.core")
            local http = require("resty.http")

            local function read(path)
                local file = assert(io.open(path, "rb"))
                local value = file:read("*a")
                file:close()
                return value
            end

            local code = t.test('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                core.json.encode({
                    uri = "/xml",
                    plugins = {
                        ["proxy-rewrite"] = {uri = "/upstream"},
                        ["xml-signer"] = {
                            credentials = {
                                certificate = read("t/certs/server.crt"),
                                private_key = read("t/certs/server.key"),
                            },
                            request = {max_body_bytes = 16384},
                        },
                    },
                    upstream = {
                        type = "roundrobin",
                        nodes = {["127.0.0.1:" .. ngx.var.server_port] = 1},
                    },
                })
            )
            if code >= 300 then
                ngx.status = code
                return
            end
            ngx.sleep(0.5)

            local function call(method, content_type, body)
                local res = assert(http.new():request_uri(
                    "http://127.0.0.1:" .. ngx.var.server_port .. "/xml",
                    {method = method, body = body,
                     headers = {["Content-Type"] = content_type}}))
                if res.status == 200 then
                    ngx.print(res.status, " ", res.body)
                else
                    ngx.say(res.status, " ", core.json.decode(res.body).message)
                end
            end

            call("POST", "application/xml",
                 '<Order xmlns="urn:test"><Item>1</Item></Order>')
            call("GET", "application/xml")
            call("POST", "application/json", "{}")
            call("POST", "application/xml", "<broken")
            local exact = "<root>" .. string.rep("x", 16371) .. "</root>"
            assert(#exact == 16384)
            call("POST", "application/xml", exact)
            call("POST", "application/xml", exact .. " ")
            call("POST", "application/xml", "")
            local chunks = 3
            local res = assert(http.new():request_uri(
                "http://127.0.0.1:" .. ngx.var.server_port .. "/xml",
                {method = "POST",
                 body = function()
                     if chunks == 0 then
                         return nil
                     end
                     chunks = chunks - 1
                     return string.rep("x", 8192)
                 end,
                 headers = {["Content-Type"] = "application/xml"}}))
            assert(res.status == 413, res.body)
            ngx.say(res.status)
        }
    }
--- request
GET /t
--- response_body
200 signatures=1 length_ok=true
200 signatures=0 length_ok=true
415 unsupported_media_type
400 invalid_xml
200 signatures=1 length_ok=true
413 body_too_large
400 empty_body
413
--- error_log
xml-signer rejected request: invalid_xml
xml-signer failed to read request body: request size 16385 is greater than the maximum size 16384 allowed
xml-signer failed to read request body: nil
