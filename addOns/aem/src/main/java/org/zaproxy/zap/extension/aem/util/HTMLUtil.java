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
		return Optional.ofNullable(msg).map(m -> m.getResponseBody()).filter(Objects::nonNull).map(b -> elem(b, css))
				.orElseGet(Optional::empty);
	}

	public static Optional<Element> elem(final HttpResponseBody body, final String css) {
		return Optional.ofNullable(body).map(m -> m.toString()).filter(StringUtils::isNoneBlank).map(b -> elem(b, css))
				.orElseGet(Optional::empty);
	}

	public static Optional<Element> elem(final String body, final String css) {
		return Optional.ofNullable(body).map(b -> Jsoup.parse(b, "http://example.com/").select(css).first())
				.filter(Objects::nonNull);
	}

}
