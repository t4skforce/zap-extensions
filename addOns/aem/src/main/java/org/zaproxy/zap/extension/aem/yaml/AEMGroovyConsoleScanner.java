package org.zaproxy.zap.extension.aem.yaml;

import java.io.IOException;
import java.net.URLEncoder;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.collections.list.UnmodifiableList;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractPlugin.AlertBuilder;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.aem.util.JsonUtil;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

public class AEMGroovyConsoleScanner {
	private static final String CSRF_TOKEN_HEADER = "CSRF-Token";

	private static final String CSRF_TOKEN_JSON = "/libs/granite/csrf/token.json";

	private static Logger LOG = Logger.getLogger(AEMGroovyConsoleScanner.class);

	private static final String EXPLOIT_CODE = "new String(\"{0}\".decodeBase64())";

	private static final String NULLBYTE = ";%0aa";

	private static final String PATH_POSTFIX = "/a";

	private static final String BASE_PATH = "/bin/groovyconsole/post";

	@SuppressWarnings("unchecked")
	private static final List<String> FILE_EXTENSIONS = UnmodifiableList.decorate(Arrays.asList(StringUtils.EMPTY,
			".json", ".servlet", ".js", ".css", ".html", ".ico", ".png", ".gif", ".swf"));

	private static final Map<String, String> DEFAULT_ACCOUNTS = new TreeMap<String, String>() {
		private static final long serialVersionUID = 3775355905080510982L;
		{
			put("author", "author");
			put("admin", "admin");
		}
	};

	private static final Tech[] SUPPORTED_TECH = new Tech[] { Tech.Apache, Tech.JAVA, Tech.Tomcat };

	public int getId() {
		return 50050;
	}

	public String getName() {
		return Constant.messages.getString("aem.groovy.scanner.name");
	}

	public String getDescription() {
		return Constant.messages.getString("aem.groovy.scanner.desc");
	}

	public int getCweId() {
		// CWE-94: Improper Control of Generation of Code ('Code Injection')
		return 94;
	}

	public int getWascId() {
		// 31: OS Commanding
		return 31;
	}

	public int getCategory() {
		return Category.INJECTION;
	}

	public String getSolution() {
		return Constant.messages.getString("aem.groovy.scanner.solution");
	}

	public String getReference() {
		// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0957
		// https://helpx.adobe.com/security/products/experience-manager/apsb16-05.html
		return Constant.messages.getString("aem.groovy.scanner.ref");
	}

	public boolean targets(TechSet technologies) {
		return technologies.includesAny(SUPPORTED_TECH);
	}

	public void scan() {
		/*
		 * URI origin = getBaseMsg().getRequestHeader().getURI();
		 *
		 * // CSRF-Token ? Map<String, String> header = new HashMap<>(); String token =
		 * getCSRFToken(origin, header); if (StringUtils.isNotBlank(token)) {
		 * header.put(CSRF_TOKEN_HEADER, token); }
		 *
		 * // no credentials tests for (URI uri : getPaths(origin)) {
		 * Optional<AlertBuilder> alert = checkVulnerability(uri, header);
		 * alert.ifPresent(ab -> ab.raise());
		 *
		 * if (isStop() || alert.isPresent()) { return; } }
		 *
		 * // default credentials test for (Entry<String, String> auth :
		 * DEFAULT_ACCOUNTS.entrySet()) { header = new HashMap<>(); // Basic
		 * Authorization Header header.put("Authorization",
		 * MessageFormat.format("Basic {0}", Base64.getEncoder()
		 * .encodeToString(MessageFormat.format("{0}:{1}", auth.getKey(),
		 * auth.getValue()).getBytes()))); // Let's check for a CSRF Token token =
		 * getCSRFToken(origin, header); if (StringUtils.isNotBlank(token)) {
		 * header.put(CSRF_TOKEN_HEADER, token); } for (URI uri : getPaths(origin)) {
		 * Optional<AlertBuilder> alert = checkVulnerability(uri, header);
		 * alert.ifPresent(ab -> ab.raise());
		 *
		 * if (isStop() || alert.isPresent()) { return; } } }
		 */
	}

	private List<URI> getPaths(final URI origin) {
		final List<URI> paths = new ArrayList<>();
		if (origin != null) {
			try {
				final String scheme = origin.getScheme();
				final String authority = origin.getAuthority();

				for (String extension : FILE_EXTENSIONS) {
					paths.add(new URI(scheme, authority, BASE_PATH + extension, null, null));
					for (String ext : FILE_EXTENSIONS) {
						paths.add(new URI(scheme, authority, BASE_PATH + extension + PATH_POSTFIX + ext, null, null));
					}
					for (String ext : FILE_EXTENSIONS) {
						paths.add(new URI(scheme, authority, BASE_PATH + extension + NULLBYTE + ext, null, null));
					}
				}
			} catch (URIException e) {
				LOG.error(e.getMessage(), e);
			}
		}
		return paths;
	}

	private Optional<AlertBuilder> checkVulnerability(URI uri, Map<String, String> headers) {
		return checkVulnerability(uri, headers, UUID.randomUUID().toString());
	}

	private Optional<AlertBuilder> checkVulnerability(URI uri, Map<String, String> headers, String testString) {
		try {
			HttpRequestHeader reqestHeader = new HttpRequestHeader(HttpRequestHeader.POST, uri, HttpHeader.HTTP11);

			// https://docs.adobe.com/content/help/en/experience-manager-65/forms/administrator-help/configure-user-management/preventing-csrf-attacks.html
			// Allowed Referer
			reqestHeader.addHeader("Referer",
					new URI(uri.getScheme(), uri.getAuthority(), null, null, null).toString());

			if (MapUtils.isNotEmpty(headers)) {
				for (Entry<String, String> header : headers.entrySet()) {
					reqestHeader.addHeader(header.getKey(), header.getValue());
				}
			}

			String exploitCode = MessageFormat.format(EXPLOIT_CODE,
					Base64.getEncoder().encodeToString(testString.getBytes()));
			String encodedExploit = MessageFormat.format("script={0}&data=", URLEncoder.encode(exploitCode, "UTF-8"));
			HttpRequestBody requestBody = new HttpRequestBody(encodedExploit);

			HttpMessage requestMessage = new HttpMessage(reqestHeader, requestBody);
			// this.sendAndReceive(requestMessage, false);

			HttpResponseHeader responseHeader = requestMessage.getResponseHeader();
			if (responseHeader.isJson()) {
				HttpResponseBody responseBody = requestMessage.getResponseBody();
				String result = JsonUtil.query(responseBody, ".result", true).get();
				if (StringUtils.equalsIgnoreCase(result, testString)) {
					// AlertBuilder alert =
					// newAlert().setEvidence(result).setMessage(requestMessage);
					// return Optional.ofNullable(alert);
				}
			} else if (responseHeader.getStatusCode() == 403) {

			}
		} catch (IOException e) {
			LOG.error(e.getMessage(), e);
		}
		return Optional.empty();
	}

	private String getCSRFToken(final URI origin, Map<String, String> headers) {
		try {
			URI uri = new URI(origin.getScheme(), origin.getAuthority(), CSRF_TOKEN_JSON, null, null);
			HttpRequestHeader reqestHeader = new HttpRequestHeader(HttpRequestHeader.GET, uri, HttpHeader.HTTP11);
			reqestHeader.addHeader("Referer", origin.toString());

			if (MapUtils.isNotEmpty(headers)) {
				for (Entry<String, String> header : headers.entrySet()) {
					reqestHeader.addHeader(header.getKey(), header.getValue());
				}
			}

			HttpMessage requestMessage = new HttpMessage(reqestHeader);
			// this.sendAndReceive(requestMessage, false);

			HttpResponseHeader responseHeader = requestMessage.getResponseHeader();
			if (responseHeader.isJson()) {
				HttpResponseBody responseBody = requestMessage.getResponseBody();
				String result = JsonUtil.query(responseBody, ".token", true).get();
				if (StringUtils.isNotBlank(result)) {
					return result;
				}
			}
		} catch (IOException e) {
			LOG.error(e.getMessage(), e);
		}
		return null;
	}

}
