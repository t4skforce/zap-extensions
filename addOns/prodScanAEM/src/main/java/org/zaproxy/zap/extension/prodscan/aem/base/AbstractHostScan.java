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
package org.zaproxy.zap.extension.prodscan.aem.base;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.prodscan.ExtensionProductScan;
import org.zaproxy.zap.extension.prodscan.util.fuzzer.HttpRequestFuzzBuilder;
import org.zaproxy.zap.extension.prodscan.util.wrapper.HttpMessageWrapper;

public abstract class AbstractHostScan extends AbstractHostPlugin {
    private static final Logger LOG = Logger.getLogger(AbstractHostScan.class);

    public AbstractHostScan() {
        super();
        Control.getSingleton().getExtensionLoader().getExtension(ExtensionProductScan.class);
    }

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
            return HttpRequestFuzzBuilder.builder(msg)
                    .setFileExtension("css", "js", "html", "ico", "png", "json", "jpg", "jpeg", "swf", "xml")
                    .appendRaw(
                            path -> Optional.ofNullable(Paths.get(path).getFileName())
                                    .map(Path::toString)
                                    .filter(f -> f.contains("."))
                                    .isPresent(),
                            "\nZAP.css", "\nZAP.js", "\nZAP.html", "\nZAP.gif", "\nZAP.png", "\nZAP.json", "\nZAP.ico",
                            "\nZAP.jpg", "\nZAP.jpeg", "\nZAP.swf", "\nZAP.xml")
                    .setPathSeparator("///")
                    .join(HttpRequestFuzzBuilder.builder(msg)
                            .appendPath("ZAP.css", "ZAP.js", "ZAP.html", "ZAP.gif", "ZAP.png", "ZAP.json", "ZAP.ico",
                                    "ZAP.jpg", "ZAP.jpeg", "ZAP.swf", "ZAP.xml", "ZAP.clientlibs", "ZAP.servlet",
                                    "ZAP.1.json", "ZAP...4.2.1...json"))
                    .join(HttpRequestFuzzBuilder.builder(msg)
                            .setQueryParam("ZAP.css", "ZAP.js", "ZAP.html", "ZAP.gif", "ZAP.png", "ZAP.json", "ZAP.ico",
                                    "ZAP.jpg", "ZAP.jpeg", "ZAP.swf", "ZAP.xml", "ZAP.clientlibs", "ZAP.servlet",
                                    "ZAP.1.json", "ZAP...4.2.1...json"))
                    .stream();
        } else if (AttackStrength.INSANE.equals(strength)) {
            // no restriction :D
            return HttpRequestFuzzBuilder.builder(msg)
                    .setFileExtension("css", "js", "html", "ico", "png", "json", "jpg", "jpeg", "swf", "xml",
                            "clientlibs", "servlet")
                    .appendRaw(
                            path -> Optional.ofNullable(Paths.get(path).getFileName())
                                    .map(Path::toString)
                                    .filter(f -> f.contains("."))
                                    .isPresent(),
                            "\nZAP.css", "\nZAP.js", "\nZAP.html", "\nZAP.gif", "\nZAP.png", "\nZAP.json", "\nZAP.ico",
                            "\nZAP.jpg", "\nZAP.jpeg", "\nZAP.swf", "\nZAP.xml", "\nZAP.clientlibs", "\nZAP.servlet")
                    .setPathSeparator("///")
                    .appendPath("ZAP.css", "ZAP.js", "ZAP.html", "ZAP.gif", "ZAP.png", "ZAP.json", "ZAP.ico", "ZAP.jpg",
                            "ZAP.jpeg", "ZAP.swf", "ZAP.xml", "ZAP.clientlibs", "ZAP.servlet", "ZAP.1.json",
                            "ZAP...4.2.1...json")
                    .setQueryParam("ZAP.css", "ZAP.js", "ZAP.html", "ZAP.gif", "ZAP.png", "ZAP.json", "ZAP.ico",
                            "ZAP.jpg", "ZAP.jpeg", "ZAP.swf", "ZAP.xml", "ZAP.clientlibs", "ZAP.servlet", "ZAP.1.json",
                            "ZAP...4.2.1...json")
                    .stream();
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

    protected static <T> T m(Callable<T> callable) {
        try {
            return callable.call();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public abstract String getMessagePrefix();

    public abstract void doScan(HttpMessage baseMessage) throws Exception;
}
