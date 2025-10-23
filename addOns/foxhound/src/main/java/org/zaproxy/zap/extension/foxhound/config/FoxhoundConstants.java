package org.zaproxy.zap.extension.foxhound.config;

import java.util.Collections;
import java.util.List;
import java.util.Set;

public class FoxhoundConstants {

    public static List<String> SOURCES;
    public static List<String> SINKS;

    // The full list can be found here: https://github.com/SAP/project-foxhound/blob/main/modules/libpref/init/all.js
    static {
        SOURCES = Collections.unmodifiableList(List.of(
            // Location Sources
            "location.hash",
            "location.host",
            "location.hostname",
            "location.href",
            "location.origin",
            "location.pathname",
            "location.port",
            "location.protocol",
            "location.search",
            "window.name",
            "document.referrer",
            "document.baseURI",
            "document.documentURI",

            // Storage
            "document.cookie",
            "localStorage.getItem",
            "sessionStorage.getItem",

            // Message Based Sources
            "MessageEvent",
            "PushMessageData",
            "PushSubscription.endpoint",
            "WebSocket.MessageEvent.data",
            "XMLHttpRequest.response",

            // Specific Element Inputs
            "input.value",
            "textarea.value",
            "script.innerHTML",

            // DOM elements and attributes
            "document.getElementById",
            "document.getElementsByTagName",
            "document.getElementsByTagNameNS",
            "document.getElementsByClassName",
            "document.querySelector",
            "document.querySelectorAll",
            "document.elementFromPoint",
            "document.elementsFromPoint",
            "element.attribute",
            "element.closest"
        ));

        SINKS = Collections.unmodifiableList(List.of(
            // Sinks
            "element.after",
            "element.before",

            "EventSource",
            "Function.ctor",
            "Range.createContextualFragment(fragment)",
            "WebSocket",
            "WebSocket.send",
            "XMLHttpRequest.open(password)",
            "XMLHttpRequest.open(url)",
            "XMLHttpRequest.open(username)",
            "XMLHttpRequest.send",
            "XMLHttpRequest.setRequestHeader(name)",
            "XMLHttpRequest.setRequestHeader(value)",
            "a.href",
            "area.href",
            "document.cookie",
            "document.writeln",
            "document.write",
            "element.style",
            "embed.src",
            "eval",
            "eventHandler",
            "fetch.body",
            "fetch.url",
            "form.action",
            "iframe.src",
            "iframe.srcdoc",
            "img.src",
            "img.srcset",
            "innerHTML",
            "insertAdjacentHTML",
            "insertAdjacentText",
            "localStorage.setItem",
            "localStorage.setItem(key)",
            "location.assign",
            "location.hash",
            "location.host",
            "location.href",
            "location.pathname",
            "location.port",
            "location.protocol",
            "location.replace",
            "location.search",
            "media.src",
            "navigator.sendBeacon(body)",
            "navigator.sendBeacon(url)",
            "object.data",
            "outerHTML",
            "script.innerHTML",
            "script.src",
            "script.text",
            "script.textContent",
            "sessionStorage.setItem",
            "sessionStorage.setItem(key)",
            "setInterval",
            "setTimeout",
            "source",
            "srcset",
            "track.src",
            "window.open",
            "window.postMessage"
        ));
    }





}
