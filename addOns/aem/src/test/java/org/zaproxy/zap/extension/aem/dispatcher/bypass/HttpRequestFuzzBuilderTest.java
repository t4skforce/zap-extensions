package org.zaproxy.zap.extension.aem.dispatcher.bypass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.file.Paths;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.httpclient.URI;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.aem.util.fuzzer.HttpRequestFuzzBuilder;
import org.zaproxy.zap.extension.aem.util.wrapper.HttpMessageWrapper;

public class HttpRequestFuzzBuilderTest {

	private HttpMessageWrapper msg;

	@Before
	public void before() throws Exception {
		HttpRequestHeader header = new HttpRequestHeader(HttpRequestHeader.GET,
				new URI("http", "www.test.local", "/", null, null), HttpRequestHeader.HTTP11);
		msg = new HttpMessageWrapper(header);
	}

	@Test
	public void testNullAppendFileExtension() throws Exception {
		String nullParam = null;
		HttpMessageWrapper nullMsg = null;
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.appendFileExtension(msg, nullParam)));
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.appendFileExtension(nullMsg, "test")));
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.appendFileExtension(nullMsg, nullParam)));
	}

	@Test
	public void testAppendFileExtension() throws Exception {
		setPath("/test.html");
		List<HttpMessageWrapper> messages = HttpRequestFuzzBuilder.appendFileExtension(msg, "json", "css");
		assertPathEquals(messages, "/test.html.json", "/test.html.css");
	}

	@Test
	public void testNullAppendPath() throws Exception {
		String nullParam = null;
		HttpMessageWrapper nullMsg = null;
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.appendPath(msg, nullParam)));
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.appendPath(nullMsg, "test")));
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.appendPath(nullMsg, nullParam)));
	}

	@Test
	public void testAppendPath() throws Exception {
		setPath("/test.html");
		List<HttpMessageWrapper> messages = HttpRequestFuzzBuilder.appendPath(msg, "json", "css");
		assertPathEquals(messages, "/test.html/json", "/test.html/css");
	}

	@Test
	public void testNullAppendRaw() throws Exception {
		String nullParam = null;
		HttpMessageWrapper nullMsg = null;
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.appendRaw(msg, nullParam)));
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.appendRaw(nullMsg, "test")));
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.appendRaw(nullMsg, nullParam)));
	}

	@Test
	public void testAppendRaw() throws Exception {
		setPath("/test.html");
		List<HttpMessageWrapper> messages = HttpRequestFuzzBuilder.appendRaw(msg, "\na.json", "\na.css");
		assertPathEquals(messages, "/test.html\na.json", "/test.html\na.css");
	}

	@Test
	public void testNullSetFileExtension() throws Exception {
		String nullParam = null;
		HttpMessageWrapper nullMsg = null;
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.setFileExtension(msg, nullParam)));
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.setFileExtension(nullMsg, "test")));
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.setFileExtension(nullMsg, nullParam)));
	}

	@Test
	public void testSetFileExtension() throws Exception {
		setPath("/test.html");
		List<HttpMessageWrapper> messages = HttpRequestFuzzBuilder.setFileExtension(msg, "json", "css");
		assertPathEquals(messages, "/test.json", "/test.css");

		setPath("/test.html.json");
		messages = HttpRequestFuzzBuilder.setFileExtension(msg, "json", "css");
		assertPathEquals(messages, "/test.json", "/test.css");

		setPath("/test");
		messages = HttpRequestFuzzBuilder.setFileExtension(msg, "json", "css");
		assertPathEquals(messages, "/test.json", "/test.css");
	}

	@Test
	public void testNullPrependFileExtension() throws Exception {
		String nullParam = null;
		HttpMessageWrapper nullMsg = null;
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.prependFileExtension(msg, nullParam)));
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.prependFileExtension(nullMsg, "test")));
		assertTrue(CollectionUtils.isEmpty(HttpRequestFuzzBuilder.prependFileExtension(nullMsg, nullParam)));
	}

	@Test
	public void testPrependFileExtension() throws Exception {
		setPath("/test.html");
		List<HttpMessageWrapper> messages = HttpRequestFuzzBuilder.prependFileExtension(msg, "json", "css");
		assertPathEquals(messages, "/test.json.html", "/test.css.html");

		setPath("/test.servlet.html");
		messages = HttpRequestFuzzBuilder.prependFileExtension(msg, "json", "css");
		assertPathEquals(messages, "/test.json.servlet.html", "/test.css.servlet.html");
	}

	@Test
	public void test() throws Exception {
		setPath("/content/test.xml");
		List<HttpMessageWrapper> messages = HttpRequestFuzzBuilder.builder(msg)
				.setFileExtension("css", "js", "html", "ico", "png", "json")
				.appendRaw(path -> Paths.get(path).getFileName().toString().contains("."), "\nZAP.css", "\nZAP.js",
						"\nZAP.html", "\nZAP.gif", "\nZAP.png", "\nZAP.json")
				.join(HttpRequestFuzzBuilder.builder(msg)
						.appendPath("ZAP.css", "ZAP.js", "ZAP.gif", "ZAP.ico", "ZAP.png", "ZAP.swf", "ZAP.jpg",
								"ZAP.jpeg", "ZAP.clientlibs", "ZAP.servlet", "ZAP.1.json", "ZAP...4.2.1...json",
								"ZAP.xml"))
				.join(HttpRequestFuzzBuilder.builder(msg)
						.setQueryParam("ZAP.css", "ZAP.js", "ZAP.clientlibs", "ZAP.servlet", "ZAP.gif", "ZAP.ico",
								"ZAP.png", "ZAP.swf", "ZAP.jpg", "ZAP.jpeg", "ZAP.1.json", "ZAP...4.2.1...json",
								"ZAP.xml"))
				.build();
		messages.forEach(m -> {
			System.out.println(m.getRequestHeader().getURI().toString());
		});
		System.out.println(messages.size());
	}

	@Test
	public void testChaining() throws Exception {
		setPath("/test");
		List<HttpMessageWrapper> messages = HttpRequestFuzzBuilder.builder(msg)
				.setFileExtension("html", "js")
				.appendFileExtension("json", "css")
				.appendPath("a.css", "a.html")
				.appendRaw("\na.css", "\na.html")
				.build();
		assertPathEquals(messages, "/test", "/test.html", "/test.js", "/test.json", "/test.css", "/test.html.json",
				"/test.html.css", "/test.js.json", "/test.js.css", "/test/a.css", "/test/a.html", "/test.html/a.css",
				"/test.html/a.html", "/test.js/a.css", "/test.js/a.html", "/test.json/a.css", "/test.json/a.html",
				"/test.css/a.css", "/test.css/a.html", "/test.html.json/a.css", "/test.html.json/a.html",
				"/test.html.css/a.css", "/test.html.css/a.html", "/test.js.json/a.css", "/test.js.json/a.html",
				"/test.js.css/a.css", "/test.js.css/a.html", "/test\na.css", "/test\na.html", "/test.html\na.css",
				"/test.html\na.html", "/test.js\na.css", "/test.js\na.html", "/test.json\na.css", "/test.json\na.html",
				"/test.css\na.css", "/test.css\na.html", "/test.html.json\na.css", "/test.html.json\na.html",
				"/test.html.css\na.css", "/test.html.css\na.html", "/test.js.json\na.css", "/test.js.json\na.html",
				"/test.js.css\na.css", "/test.js.css\na.html", "/test/a.css\na.css", "/test/a.css\na.html",
				"/test/a.html\na.css", "/test/a.html\na.html", "/test.html/a.css\na.css", "/test.html/a.css\na.html",
				"/test.html/a.html\na.css", "/test.html/a.html\na.html", "/test.js/a.css\na.css",
				"/test.js/a.css\na.html", "/test.js/a.html\na.css", "/test.js/a.html\na.html",
				"/test.json/a.css\na.css", "/test.json/a.css\na.html", "/test.json/a.html\na.css",
				"/test.json/a.html\na.html", "/test.css/a.css\na.css", "/test.css/a.css\na.html",
				"/test.css/a.html\na.css", "/test.css/a.html\na.html", "/test.html.json/a.css\na.css",
				"/test.html.json/a.css\na.html", "/test.html.json/a.html\na.css", "/test.html.json/a.html\na.html",
				"/test.html.css/a.css\na.css", "/test.html.css/a.css\na.html", "/test.html.css/a.html\na.css",
				"/test.html.css/a.html\na.html", "/test.js.json/a.css\na.css", "/test.js.json/a.css\na.html",
				"/test.js.json/a.html\na.css", "/test.js.json/a.html\na.html", "/test.js.css/a.css\na.css",
				"/test.js.css/a.css\na.html", "/test.js.css/a.html\na.css", "/test.js.css/a.html\na.html");
	}

	private void assertPathEquals(List<HttpMessageWrapper> msgs, String... paths) throws Exception {
		URI origin = msg.getRequestHeader().getURI();
		assertEquals(paths.length, msgs.size());
		for (int i = 0; i < paths.length; i++) {
			String suffix = paths[i];
			HttpMessage message = msgs.get(i);
			assertNotNull(message);
			HttpRequestHeader header = message.getRequestHeader();
			assertNotNull(header);
			URI uri = header.getURI();
			assertNotNull(uri);
			assertEquals(origin.getScheme(), uri.getScheme());
			assertEquals(origin.getAuthority(), uri.getAuthority());
			assertEquals(origin.getQuery(), uri.getQuery());
			assertEquals(origin.getFragment(), uri.getFragment());
			assertEquals(suffix, uri.getPath());
		}
	}

	private void setPath(String path) throws Exception {
		HttpRequestHeader header = msg.getRequestHeader();
		URI origin = header.getURI();
		header.setURI(new URI(origin.getScheme(), origin.getAuthority(), path, null, null));
	}
}
