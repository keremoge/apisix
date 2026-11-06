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

=== TEST 1: validate schema
--- apisix_yaml
routes: []
#END
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.xml-signer")
            local ok = plugin.check_schema({
                credentials = {
                    certificate = "$secret://vault/signing/certificate",
                    private_key = "$secret://vault/signing/private-key",
                },
            })
            ngx.say(ok)

            ok = plugin.check_schema({
                credentials = {certificate = "certificate"},
            })
            ngx.say(ok)

            ok = plugin.check_schema({
                credentials = {
                    certificate = "certificate",
                    private_key = "private-key",
                },
                signature = {algorithm = "rsa-sha1"},
            })
            ngx.say(ok)

            ok = plugin.check_schema({
                credentials = {
                    certificate = "certificate",
                    private_key = "private-key",
                },
                signature = {algorithm = "rsa-sha512"},
            })
            ngx.say(ok)
        }
    }
--- request
GET /t
--- response_body
true
false
true
false



=== TEST 2: sign and verify enveloped XMLDSig
--- apisix_yaml
routes: []
#END
--- config
    location /t {
        content_by_lua_block {
            local digest = require("resty.openssl.digest")
            local x509 = require("resty.openssl.x509")
            local signer = require("apisix.plugins.xml-signer.signer")
            local xml = require("apisix.plugins.xml-signer.xml")

            local function read(path)
                local file = assert(io.open(path, "rb"))
                local value = file:read("*a")
                file:close()
                return value
            end

            local certificate_pem = read("t/certs/server.crt")
            local signed = assert(signer.sign(
                '<?xml version="1.0" encoding="ISO-8859-1"?>'
                .. '<?before-signing preserve?>'
                .. '<root xmlns="urn:test"><value>42 \195\169</value></root>'
                .. '<?after-signing preserve?>',
                {credentials = {
                    certificate = certificate_pem,
                    private_key = read("t/certs/server.key"),
                }},
                "UTF-8"
            ))

            local doc = assert(xml.parse(signed))
            local root = assert(xml.root(doc))
            local value = assert(xml.find_child(root, "urn:test", "value"))
            assert(xml.content(value) == "42 \195\169")
            local signature = assert(xml.find_all(
                root, signer.namespaces.ds, "Signature")[1])
            local signed_info = assert(xml.find_child(
                signature, signer.namespaces.ds, "SignedInfo"))
            local signature_value = assert(xml.find_child(
                signature, signer.namespaces.ds, "SignatureValue"))
            local reference = assert(xml.find_child(
                signed_info, signer.namespaces.ds, "Reference"))
            local digest_value = assert(xml.find_child(
                reference, signer.namespaces.ds, "DigestValue"))

            local canonical_signed_info = assert(xml.canonicalize(signed_info))
            local raw_signature = assert(ngx.decode_base64(xml.content(signature_value)))
            local certificate = assert(x509.new(certificate_pem, "PEM"))
            local public_key = assert(certificate:get_pubkey())
            assert(public_key:verify(raw_signature, canonical_signed_info, "sha256"))

            local expected_digest = xml.content(digest_value)
            xml.remove(signature)
            local canonical_document = assert(xml.canonicalize_document(doc))
            local context = assert(digest.new("sha256"))
            assert(context:update(canonical_document))
            assert(ngx.encode_base64(assert(context:final())) == expected_digest)
            xml.free_document(doc)
            ngx.say("verified")
        }
    }
--- request
GET /t
--- response_body
verified



=== TEST 3: reject unsafe and already signed XML
--- apisix_yaml
routes: []
#END
--- config
    location /t {
        content_by_lua_block {
            local signer = require("apisix.plugins.xml-signer.signer")
            local credentials = {
                certificate = "unused",
                private_key = "unused",
            }
            local _, code = signer.sign(
                '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                .. '<root>&xxe;</root>',
                {credentials = credentials}
            )
            ngx.say(code)

            _, code = signer.sign(
                '<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
                .. '<ds:Signature/></root>',
                {credentials = credentials}
            )
            ngx.say(code)
        }
    }
--- request
GET /t
--- response_body
invalid_xml
already_signed



=== TEST 4: reject non-RSA credentials
--- apisix_yaml
routes: []
#END
--- config
    location /t {
        content_by_lua_block {
            local credentials = require("apisix.plugins.xml-signer.credentials")

            local function read(path)
                local file = assert(io.open(path, "rb"))
                local value = file:read("*a")
                file:close()
                return value
            end

            local runtime, err = credentials.load({
                certificate = read("t/certs/apisix_ecc.crt"),
                private_key = read("t/certs/apisix_ecc.key"),
            })
            ngx.say(runtime == nil)
            ngx.say(err)
        }
    }
--- request
GET /t
--- response_body
true
private key must be RSA



=== TEST 5: sign and verify XMLDSig with RSA-SHA1
--- apisix_yaml
routes: []
#END
--- config
    location /t {
        content_by_lua_block {
            local digest = require("resty.openssl.digest")
            local x509 = require("resty.openssl.x509")
            local signer = require("apisix.plugins.xml-signer.signer")
            local xml = require("apisix.plugins.xml-signer.xml")

            local function read(path)
                local file = assert(io.open(path, "rb"))
                local value = file:read("*a")
                file:close()
                return value
            end

            local certificate_pem = read("t/certs/server.crt")
            local signed = assert(signer.sign(
                '<root xmlns="urn:test"><legacy>true</legacy></root>',
                {
                    credentials = {
                        certificate = certificate_pem,
                        private_key = read("t/certs/server.key"),
                    },
                    signature = {algorithm = "rsa-sha1"},
                }
            ))

            local doc = assert(xml.parse(signed))
            local root = assert(xml.root(doc))
            local signature = assert(xml.find_all(
                root, signer.namespaces.ds, "Signature")[1])
            local signed_info = assert(xml.find_child(
                signature, signer.namespaces.ds, "SignedInfo"))
            local signature_method = assert(xml.find_child(
                signed_info, signer.namespaces.ds, "SignatureMethod"))
            assert(xml.get_property(signature_method, "Algorithm")
                   == signer.namespaces.ds .. "rsa-sha1")

            local reference = assert(xml.find_child(
                signed_info, signer.namespaces.ds, "Reference"))
            local digest_method = assert(xml.find_child(
                reference, signer.namespaces.ds, "DigestMethod"))
            assert(xml.get_property(digest_method, "Algorithm")
                   == signer.namespaces.ds .. "sha1")
            local digest_value = assert(xml.find_child(
                reference, signer.namespaces.ds, "DigestValue"))

            local signature_value = assert(xml.find_child(
                signature, signer.namespaces.ds, "SignatureValue"))
            local canonical_signed_info = assert(xml.canonicalize(signed_info))
            local raw_signature = assert(ngx.decode_base64(xml.content(signature_value)))
            local certificate = assert(x509.new(certificate_pem, "PEM"))
            local public_key = assert(certificate:get_pubkey())
            assert(public_key:verify(raw_signature, canonical_signed_info, "sha1"))

            local expected_digest = xml.content(digest_value)
            xml.remove(signature)
            local canonical_document = assert(xml.canonicalize(root))
            local context = assert(digest.new("sha1"))
            assert(context:update(canonical_document))
            assert(ngx.encode_base64(assert(context:final())) == expected_digest)
            xml.free_document(doc)
            ngx.say("verified rsa-sha1")
        }
    }
--- request
GET /t
--- response_body
verified rsa-sha1



=== TEST 6: sign XML without KeyInfo
--- apisix_yaml
routes: []
#END
--- config
    location /t {
        content_by_lua_block {
            local signer = require("apisix.plugins.xml-signer.signer")
            local xml = require("apisix.plugins.xml-signer.xml")

            local function read(path)
                local file = assert(io.open(path, "rb"))
                local value = file:read("*a")
                file:close()
                return value
            end

            local signed = assert(signer.sign(
                '<root xmlns="urn:test"><value>42</value></root>',
                {
                    credentials = {
                        certificate = read("t/certs/server.crt"),
                        private_key = read("t/certs/server.key"),
                    },
                    signature = {
                        algorithm = "rsa-sha256",
                        key_info = "none",
                    },
                }
            ))

            local doc = assert(xml.parse(signed))
            local root = assert(xml.root(doc))
            assert(#xml.find_all(root, signer.namespaces.ds, "Signature") == 1)
            assert(#xml.find_all(root, signer.namespaces.ds, "KeyInfo") == 0)
            xml.free_document(doc)
            ngx.say("signed without KeyInfo")
        }
    }
--- request
GET /t
--- response_body
signed without KeyInfo



=== TEST 7: verify namespace conflicts and processing instructions without signer C14N
--- apisix_yaml
routes: []
#END
--- config
    location /t {
        content_by_lua_block {
            local digest = require("resty.openssl.digest")
            local x509 = require("resty.openssl.x509")
            local signer = require("apisix.plugins.xml-signer.signer")
            local xml = require("apisix.plugins.xml-signer.xml")
            local ds = signer.namespaces.ds
            local exclusive = "http://www.w3.org/2001/10/xml-exc-c14n#"
            local signature_uri = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            local digest_uri = "http://www.w3.org/2001/04/xmlenc#sha256"

            local function read(path)
                local file = assert(io.open(path, "rb"))
                local value = file:read("*a")
                file:close()
                return value
            end

            local certificate_pem = read("t/certs/server.crt")
            local signed = assert(signer.sign(
                '<?before preserve?><root xmlns="urn:test" xmlns:ds="urn:occupied">'
                .. '<!--not signed--><ds:item>1</ds:item>'
                .. '<plain xmlns="">note</plain></root><?after preserve?>',
                {credentials = {
                    certificate = certificate_pem,
                    private_key = read("t/certs/server.key"),
                }}
            ))
            local expected_document = '<?before preserve?>\n<root xmlns="urn:test">'
                .. '<ds:item xmlns:ds="urn:occupied">1</ds:item>'
                .. '<plain xmlns="">note</plain></root>\n<?after preserve?>'
            local context = assert(digest.new("sha256"))
            assert(context:update(expected_document))
            local expected_digest = ngx.encode_base64(assert(context:final()))

            local doc = assert(xml.parse(signed))
            local root = assert(xml.root(doc))
            local signature = assert(xml.find_all(root, ds, "Signature")[1])
            local actual_digest = assert(xml.find_all(signature, ds, "DigestValue")[1])
            assert(xml.content(actual_digest) == expected_digest)
            local expected_info = '<ds1:SignedInfo xmlns:ds1="' .. ds .. '">'
                .. '<ds1:CanonicalizationMethod Algorithm="' .. exclusive
                .. '"></ds1:CanonicalizationMethod>'
                .. '<ds1:SignatureMethod Algorithm="' .. signature_uri
                .. '"></ds1:SignatureMethod><ds1:Reference URI=""><ds1:Transforms>'
                .. '<ds1:Transform Algorithm="' .. ds .. 'enveloped-signature">'
                .. '</ds1:Transform><ds1:Transform Algorithm="' .. exclusive
                .. '"></ds1:Transform></ds1:Transforms>'
                .. '<ds1:DigestMethod Algorithm="' .. digest_uri
                .. '"></ds1:DigestMethod><ds1:DigestValue>' .. expected_digest
                .. '</ds1:DigestValue></ds1:Reference></ds1:SignedInfo>'
            local value = assert(xml.find_child(signature, ds, "SignatureValue"))
            local certificate = assert(x509.new(certificate_pem, "PEM"))
            local public_key = assert(certificate:get_pubkey())
            assert(public_key:verify(
                assert(ngx.decode_base64(xml.content(value))), expected_info, "sha256"))
            xml.free_document(doc)
            ngx.say("independent canonical form verified")
        }
    }
--- request
GET /t
--- response_body
independent canonical form verified
