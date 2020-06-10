package org.zaproxy.zap.extension.aem.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Optional;

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

	public static final Optional<String> query(final HttpMessage msg, final String query) {
		return query(msg, query, true);
	}

	public static final Optional<String> query(final HttpMessage msg, final String query, final Boolean raw) {
		return Optional.ofNullable(msg)
				.filter(m -> m.getRequestHeader().isText())
				.map(m -> m.getResponseBody().toString())
				.map(s -> query(new ByteArrayInputStream(s.getBytes()), query, raw))
				.orElse(Optional.empty());
	}

	public static final Optional<String> query(final HttpResponseBody body, final String query) {
		return query(new ByteArrayInputStream(body.getBytes()), query);
	}

	public static final Optional<String> query(final HttpResponseBody body, final String query, final Boolean raw) {
		return query(new ByteArrayInputStream(body.getBytes()), query, raw);
	}

	public static final Optional<String> query(final String body, final String query) {
		return query(new ByteArrayInputStream(body.getBytes()), query);
	}

	public static final Optional<String> query(final String body, final String query, final Boolean raw) {
		return query(new ByteArrayInputStream(body.getBytes()), query, raw);
	}

	public static final Optional<String> query(final InputStream body, final String query) {
		return query(body, query, true);
	}

	public static final Optional<String> query(final InputStream body, final String query, final Boolean raw) {
		StringBuilder sb = new StringBuilder();
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
							try {
								if (BooleanUtils.isTrue(raw)) {
									sb.append(out.asText());
								} else {
									sb.append(MAPPER.writeValueAsString(out));
								}
							} catch (IOException e) {
								throw new RuntimeException(e);
							}
						});
					} catch (JsonQueryException e) {
						LOG.error(e.getMessage(), e);
					}
				}
			}
		} catch (Exception e) {
			LOG.error(e.getMessage(), e);
		}
		return Optional.of(sb)
				.map(StringBuilder::toString)
				.map(StringUtils::stripToEmpty)
				.filter(StringUtils::isNotEmpty);
	}

}
