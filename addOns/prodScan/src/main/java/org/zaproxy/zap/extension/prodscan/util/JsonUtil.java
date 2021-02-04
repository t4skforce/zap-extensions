/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.prodscan.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.network.HttpResponseBody;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.thisptr.jackson.jq.BuiltinFunctionLoader;
import net.thisptr.jackson.jq.JsonQuery;
import net.thisptr.jackson.jq.Scope;
import net.thisptr.jackson.jq.Version;
import net.thisptr.jackson.jq.Versions;
import net.thisptr.jackson.jq.exception.JsonQueryException;
import net.thisptr.jackson.jq.internal.functions.EnvFunction;

public abstract class JsonUtil {
    private static Logger LOG = Logger.getLogger(JsonUtil.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Version VERSION = Versions.JQ_1_6;

    public static final Optional<String> string(final HttpMessage msg, final String query) {
        return string(msg, query, true);
    }

    public static final Optional<String> string(final HttpMessage msg, final String query, final Boolean raw) {
        return Optional.ofNullable(msg)
                .filter(m -> m.getRequestHeader().isText())
                .map(m -> m.getResponseBody().toString())
                .map(s -> string(new ByteArrayInputStream(s.getBytes()), query, raw))
                .orElse(Optional.empty());
    }

    public static final Optional<String> string(final HttpResponseBody body, final String query) {
        return string(new ByteArrayInputStream(body.getBytes()), query);
    }

    public static final Optional<String> string(final HttpResponseBody body, final String query, final Boolean raw) {
        return string(new ByteArrayInputStream(body.getBytes()), query, raw);
    }

    public static final Optional<String> string(final String body, final String query) {
        return string(new ByteArrayInputStream(body.getBytes()), query);
    }

    public static final Optional<String> string(final String body, final String query, final Boolean raw) {
        return string(new ByteArrayInputStream(body.getBytes()), query, raw);
    }

    public static final Optional<String> string(final InputStream body, final String query) {
        return string(body, query, true);
    }

    public static final Optional<String> string(final InputStream body, final String query, final Boolean raw) {
        return query(body, query, raw).map(nodes -> {
            StringBuilder sb = new StringBuilder();
            for (JsonNode node : nodes) {
                try {
                    if (BooleanUtils.isTrue(raw)) {
                        sb.append(node.asText());
                    } else {
                        sb.append(MAPPER.writeValueAsString(node));
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            return StringUtils.trimToEmpty(sb.toString());
        }).filter(StringUtils::isNotEmpty);
    }

    public static final Optional<List<String>> strings(final HttpMessage msg, final String query) {
        return strings(msg, query, true);
    }

    public static final Optional<List<String>> strings(final HttpMessage msg, final String query, final Boolean raw) {
        return Optional.ofNullable(msg)
                .filter(m -> m.getRequestHeader().isText())
                .map(m -> m.getResponseBody().toString())
                .map(s -> strings(new ByteArrayInputStream(s.getBytes()), query, raw))
                .orElse(Optional.empty());
    }

    public static final Optional<List<String>> strings(final InputStream body, final String query, final Boolean raw) {
        return query(body, query, raw).map(nodes -> {
            List<String> strings = new ArrayList<>();
            for (JsonNode node : nodes) {
                try {
                    String value = StringUtils.EMPTY;
                    if (BooleanUtils.isTrue(raw)) {
                        value = node.asText();
                    } else {
                        value = MAPPER.writeValueAsString(node);
                    }
                    value = StringUtils.trimToEmpty(value);
                    if (StringUtils.isNoneEmpty(value)) {
                        strings.add(value);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            return strings;
        }).filter(CollectionUtils::isNotEmpty);
    }

    public static final Optional<List<JsonNode>> query(final HttpMessage msg, final String query) {
        return query(msg, query, true);
    }

    public static final Optional<List<JsonNode>> query(final HttpMessage msg, final String query, final Boolean raw) {
        return Optional.ofNullable(msg)
                .filter(m -> m.getRequestHeader().isText())
                .map(m -> m.getResponseBody().toString())
                .map(s -> query(new ByteArrayInputStream(s.getBytes()), query, raw))
                .orElse(Optional.empty());
    }

    public static final Optional<List<JsonNode>> query(final InputStream body, final String query, final Boolean raw) {
        List<JsonNode> nodes = new ArrayList<>();
        try {
            JsonQuery jq = JsonQuery.compile(query, VERSION);
            Scope scope = Scope.newEmptyScope();
            BuiltinFunctionLoader.getInstance().loadFunctions(VERSION, scope);
            scope.addFunction("env", 0, new EnvFunction());
            try (final BufferedReader reader = new BufferedReader(new InputStreamReader(body))) {
                JsonParser parser = MAPPER.getFactory().createParser(reader);
                while (!parser.isClosed()) {
                    JsonNode tree = parser.readValueAsTree();
                    if (tree == null) {
                        continue;
                    }
                    try {
                        jq.apply(scope, tree, (out) -> {
                            nodes.add(out);
                        });
                    } catch (JsonQueryException e) {
                        LOG.error(e.getMessage(), e);
                    }
                }
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
        return Optional.of(nodes).filter(CollectionUtils::isNotEmpty);
    }

}
