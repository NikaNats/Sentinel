// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// ZAP Authentication Script for DPoP-authenticated scanning through sentinel-dast-auth-proxy.
// The proxy handles all DPoP signing transparently (fresh token + proof per request).
// This script simply marks the context as authenticated so ZAP uses the authenticated
// scan policy and reports findings against authenticated endpoints.
//
// No actual login is needed - the proxy's client_credentials + DPoP flow happens
// automatically on every forwarded request.
//
// Usage: Add as "script" authentication method in ZAP automation plan.

var PROXY_URL = "http://dast-auth-proxy:8080";
var HEALTH_ENDPOINT = PROXY_URL + "/proxy-health";

function authenticate(helper, paramsValues) {
    // Verify the proxy is reachable and healthy
    var response = helper.sendRequest(HEALTH_ENDPOINT, "GET", {}, "");
    
    if (response.getResponseHeader().getStatusCode() == 200) {
        // Proxy is healthy - mark as authenticated
        helper.getContext().setAuthenticationToken("dpop-proxy-authenticated");
        return {
            "loggedIn": true,
            "token": "dpop-proxy-authenticated"
        };
    } else {
        return {
            "loggedIn": false,
            "error": "DPoP proxy health check failed: " + response.getResponseHeader().getStatusCode()
        };
    }
}

function isLoggedIn(helper) {
    var token = helper.getContext().getAuthenticationToken();
    return token != null && token == "dpop-proxy-authenticated";
}

function getAuthenticationToken(helper) {
    return helper.getContext().getAuthenticationToken();
}

function setAuthenticationToken(helper, token) {
    helper.getContext().setAuthenticationToken(token);
}

function getLoggedInIndicator() {
    return "200";
}

function getLoggedOutIndicator() {
    return "401";
}