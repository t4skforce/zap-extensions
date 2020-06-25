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
package org.zaproxy.zap.extension.aem.util;

import java.util.Objects;
import java.util.Optional;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.network.HttpResponseBody;

public abstract class HTMLUtil {

    public static Optional<String> outerHtml(final HttpMessage msg, final String css) {
        return elem(msg, css).map(e -> e.outerHtml());
    }

    public static Optional<String> outerHtml(final HttpResponseBody body, final String css) {
        return elem(body, css).map(e -> e.outerHtml());
    }

    public static Optional<String> outerHtml(final String body, final String css) {
        return elem(body, css).map(e -> e.outerHtml());
    }

    public static Optional<String> html(final HttpMessage msg, final String css) {
        return elem(msg, css).map(e -> e.html());
    }

    public static Optional<String> html(final HttpResponseBody body, final String css) {
        return elem(body, css).map(e -> e.html());
    }

    public static Optional<String> html(final String body, final String css) {
        return elem(body, css).map(e -> e.html());
    }

    public static Optional<String> text(final HttpMessage msg, final String css) {
        return elem(msg, css).map(e -> e.text());
    }

    public static Optional<String> text(final HttpResponseBody body, final String css) {
        return elem(body, css).map(e -> e.text());
    }

    public static Optional<String> text(final String body, final String css) {
        return elem(body, css).map(e -> e.text());
    }

    public static Optional<Element> elem(final HttpMessage msg, final String css) {
        return Optional.ofNullable(msg)
                .map(m -> m.getResponseBody())
                .filter(Objects::nonNull)
                .map(b -> elem(b, css))
                .orElseGet(Optional::empty);
    }

    public static Optional<Element> elem(final HttpResponseBody body, final String css) {
        return Optional.ofNullable(body)
                .map(m -> m.toString())
                .filter(StringUtils::isNoneBlank)
                .map(b -> elem(b, css))
                .orElseGet(Optional::empty);
    }

    public static Optional<Element> elem(final String body, final String css) {
        return Optional.ofNullable(body)
                .map(b -> Jsoup.parse(b, "http://example.com/").select(css).first())
                .filter(Objects::nonNull);
    }
}
