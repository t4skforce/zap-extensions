package org.zaproxy.zap.extension.aem.base;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.aem.util.fuzzer.HttpRequestFuzzBuilder;
import org.zaproxy.zap.extension.aem.util.wrapper.HttpMessageWrapper;

public abstract class AbstractHostScan extends AbstractHostPlugin {
	private static final Logger LOG = Logger.getLogger(AbstractHostScan.class);

	@Override
	public String getName() {
		return Constant.messages.getString(getMessagePrefix() + ".name");
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString(getMessagePrefix() + ".description");
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString(getMessagePrefix() + ".solution");
	}

	@Override
	public String getReference() {
		return Constant.messages.getString(getMessagePrefix() + ".reference");
	}

	@Override
	public void scan() {
		try {
			doScan(getBaseMsg());
		} catch (StopException e) {
			// ignore
		} catch (Exception e) {
			LOG.error(e.getMessage(), e);
		}
	}

	protected class StopException extends RuntimeException {
		private static final long serialVersionUID = -4137412842407396400L;

		public StopException() {
			super();
		}

	}

	protected class PluginException extends RuntimeException {
		private static final long serialVersionUID = -5880584622913775404L;

		public PluginException(Throwable cause) {
			super(cause);
		}
	}

	protected Stream<HttpMessageWrapper> fuzzDispatcher(HttpMessage msg) {
		AttackStrength strength = getAttackStrength();
		if (AttackStrength.LOW.equals(strength)) {
			// 36 requests
			return HttpRequestFuzzBuilder.builder(msg)
					.setFileExtension("css", "js", "png", "ico")
					.appendRaw(path -> Optional.ofNullable(Paths.get(path).getFileName())
							.map(Path::toString)
							.filter(f -> f.contains("."))
							.isPresent(), "\nZAP.css", "\nZAP.js", "\nZAP.png", "\nZAP.ico", "\nZAP.json")
					.join(HttpRequestFuzzBuilder.builder(msg)
							.setPathSeparator("///")
							.setFileExtension("css", "js", "png", "ico"))
					.stream();
		} else if (AttackStrength.MEDIUM.equals(strength)) {
			// 72 requests
			return HttpRequestFuzzBuilder.builder(msg)
					.setFileExtension("css", "js", "html", "ico", "png", "json")
					.appendRaw(
							path -> Optional.ofNullable(Paths.get(path).getFileName())
									.map(Path::toString)
									.filter(f -> f.contains("."))
									.isPresent(),
							"\nZAP.css", "\nZAP.js", "\nZAP.html", "\nZAP.gif", "\nZAP.png", "\nZAP.json")
					.join(HttpRequestFuzzBuilder.builder(msg)
							.appendPath("ZAP.css", "ZAP.js", "ZAP.gif", "ZAP.ico", "ZAP.png", "ZAP.swf", "ZAP.jpg",
									"ZAP.jpeg", "ZAP.clientlibs", "ZAP.servlet", "ZAP.1.json", "ZAP...4.2.1...json",
									"ZAP.xml"))
					.join(HttpRequestFuzzBuilder.builder(msg)
							.setQueryParam("ZAP.css", "ZAP.js", "ZAP.clientlibs", "ZAP.servlet", "ZAP.gif", "ZAP.ico",
									"ZAP.png", "ZAP.swf", "ZAP.jpg", "ZAP.jpeg", "ZAP.1.json", "ZAP...4.2.1...json",
									"ZAP.xml"))
					.stream();
		} else if (AttackStrength.HIGH.equals(strength)) {
			// 288 requests
			// TODO: high scan fuzzing
		} else if (AttackStrength.INSANE.equals(strength)) {
			// no restriction :D
			// TODO: full fuzzing
		}
		return Stream.of(new HttpMessageWrapper(msg));
	}

	@FunctionalInterface
	protected interface CheckedFunction<T, R> {
		R apply(T t) throws Exception;
	}

	@FunctionalInterface
	protected interface CheckedPredicate<T, E extends Exception> {
		boolean test(T t) throws E;
	}

	protected <T, R> Function<T, R> stopMap(CheckedFunction<T, R> checkedFunction) {
		return t -> {
			try {
				if (isStop()) {
					throw new StopException();
				}
				return checkedFunction.apply(t);
			} catch (Exception e) {
				throw new PluginException(e);
			}
		};
	}

	protected <T> Predicate<T> stopFilter(CheckedPredicate<? super T, ?> predicate) {
		return t -> {
			try {
				if (isStop()) {
					throw new StopException();
				}
				return predicate.test(t);
			} catch (final Exception e) {
				throw new PluginException(e);
			}
		};
	}

	protected Predicate<? super HttpMessageWrapper> sendAndReceive(
			CheckedPredicate<? super HttpMessageWrapper, ?> predicate) {
		return sendAndReceive(predicate, true);
	}

	protected Predicate<? super HttpMessageWrapper> sendAndReceive(
			CheckedPredicate<? super HttpMessageWrapper, ?> predicate, boolean isFollowRedirect) {
		return sendAndReceive(predicate, isFollowRedirect, true);
	}

	protected Predicate<? super HttpMessageWrapper> sendAndReceive(
			CheckedPredicate<? super HttpMessageWrapper, ?> predicate, boolean isFollowRedirect,
			boolean handleAntiCSRF) {
		return t -> {
			try {
				if (isStop()) {
					throw new StopException();
				}
				sendAndReceive(t, isFollowRedirect, handleAntiCSRF);
				return predicate.test(t);
			} catch (final Exception e) {
				throw new PluginException(e);
			}
		};
	}

	public abstract String getMessagePrefix();

	public abstract void doScan(HttpMessage baseMessage) throws Exception;

}
