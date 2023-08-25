#include "http.h"
#include "util.h"

char *http_method_name(int http_method) {
    if (http_method == HTTP_METHOD_GET) {
        return "GET";
    } else if (http_method == HTTP_METHOD_HEAD) {
        return "HEAD";
    } else if (http_method == HTTP_METHOD_POST) {
        return "POST";
    } else if (http_method == HTTP_METHOD_PUT) {
        return "PUT";
    } else if (http_method == HTTP_METHOD_DELETE) {
        return "DELETE";
    } else if (http_method == HTTP_METHOD_CONNECT) {
        return "CONNECT";
    } else if (http_method == HTTP_METHOD_OPTIONS) {
        return "OPTIONS";
    } else if (http_method == HTTP_METHOD_TRACE) {
        return "TRACE";
    } else if (http_method == HTTP_METHOD_PATCH) {
        return "PATCH";
    } else {
        errorf("unknown http method: %i", http_method);
        return "UNKOWN";
    }
}

int parse_http_method(char *method) {
    if (strcmp(method, "GET") == 0) {
        return HTTP_METHOD_GET;
    } else if (strcmp(method, "HEAD") == 0) {
        return HTTP_METHOD_HEAD;
    } else if (strcmp(method, "POST") == 0) {
        return HTTP_METHOD_POST;
    } else if (strcmp(method, "PUT") == 0) {
        return HTTP_METHOD_PUT;
    } else if (strcmp(method, "DELETE") == 0) {
        return HTTP_METHOD_DELETE;
    } else if (strcmp(method, "CONNECT") == 0) {
        return HTTP_METHOD_CONNECT;
    } else if (strcmp(method, "OPTIONS") == 0) {
        return HTTP_METHOD_OPTIONS;
    } else if (strcmp(method, "TRACE") == 0) {
        return HTTP_METHOD_TRACE;
    } else if (strcmp(method, "PATCH") == 0) {
        return HTTP_METHOD_PATCH;
    } else {
        // extension methodの可能性があるので本来はエラーではない
        errorf("unknown http method: %s", method);
        return -1;
    }
}

int parse_http_version(char *version_string) {
    if (strncmp(version_string, "HTTP/", 5) != 0) {
        errorf("http protocol error: version string");
        return -1;
    }

    if (strncmp(&version_string[5], "1.0", 3) == 0) {
        return HTTP_VERSION_1_0;
    } else if (strncmp(&version_string[5], "1.1", 3) == 0) {
        return HTTP_VERSION_1_1;
    } else {
        errorf("http version parse error: unsupported version: %s", version_string);
        return -1;
    }
}

char *http_version_name(int http_version) {
    if (http_version == HTTP_VERSION_1_0) {
        return "1.0";
    } else if (http_version == HTTP_VERSION_1_1) {
        return "1.1";
    } else {
        errorf("unknown http version");
        return "UNKNOWN";
    }
}

char *http_status_text(int status_code) {
    if (status_code == HTTP_STATUS_CONTINUE) { return "Continue"; }
    else if (status_code == HTTP_STATUS_SWITCHING_PROTOCOLS) { return "Switching Protocols"; }
    else if (status_code == HTTP_STATUS_OK) { return "OK"; }
    else if (status_code == HTTP_STATUS_CREATED) { return "Created"; }
    else if (status_code == HTTP_STATUS_ACCEPTED) { return "Accepted"; }
    else if (status_code == HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION) { return "Non-Authoritative Information"; }
    else if (status_code == HTTP_STATUS_NO_CONTENT) { return "No Content"; }
    else if (status_code == HTTP_STATUS_RESET_CONTENT) { return "Reset Content"; }
    else if (status_code == HTTP_STATUS_PARTIAL_CONTENT) { return "Partial Content"; }
    else if (status_code == HTTP_STATUS_MULTIPLE_CHOICES) { return "Multiple Choices"; }
    else if (status_code == HTTP_STATUS_MOVED_PERMANENTLY) { return "Moved Permanently"; }
    else if (status_code == HTTP_STATUS_FOUND) { return "Found"; }
    else if (status_code == HTTP_STATUS_SEE_OTHER) { return "See Other"; }
    else if (status_code == HTTP_STATUS_NOT_MODIFIED) { return "Not Modified"; }
    else if (status_code == HTTP_STATUS_USE_PROXY) { return "Use Proxy"; }
    else if (status_code == HTTP_STATUS_TEMPORARY_REDIRECT) { return "Temporary Redirect"; }
    else if (status_code == HTTP_STATUS_BAD_REQUEST) { return "Bad Request"; }
    else if (status_code == HTTP_STATUS_UNAUTHORIZED) { return "Unauthorized"; }
    else if (status_code == HTTP_STATUS_PAYMENT_REQUIRED) { return "Payment Required"; }
    else if (status_code == HTTP_STATUS_FORBIDDEN) { return "Forbidden"; }
    else if (status_code == HTTP_STATUS_NOT_FOUND) { return "Not Found"; }
    else if (status_code == HTTP_STATUS_METHOD_NOT_ALLOWED) { return "Method Not Allowed"; }
    else if (status_code == HTTP_STATUS_NOT_ACCEPTABLE) { return "Not Acceptable"; }
    else if (status_code == HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED) { return "Proxy Authentication Required"; }
    else if (status_code == HTTP_STATUS_REQUEST_TIMEOUT) { return "Request Time-out"; }
    else if (status_code == HTTP_STATUS_CONFLICT) { return "Conflict"; }
    else if (status_code == HTTP_STATUS_GONE) { return "Gone"; }
    else if (status_code == HTTP_STATUS_LENGTH_REQUIRED) { return "Length Required"; }
    else if (status_code == HTTP_STATUS_PRECONDITION_FAILED) { return "Precondition Failed"; }
    else if (status_code == HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE) { return "Request Entity Too Large"; }
    else if (status_code == HTTP_STATUS_REQUEST_URI_TOO_LARGE) { return "Request-URI Too Large"; }
    else if (status_code == HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE) { return "Unsupported Media Type"; }
    else if (status_code == HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE) { return "Requested range not satisfiable"; }
    else if (status_code == HTTP_STATUS_EXPECTATION_FAILED) { return "Expectation Failed"; }
    else if (status_code == HTTP_STATUS_INTERNAL_SERVER_ERROR) { return "Internal Server Error"; }
    else if (status_code == HTTP_STATUS_NOT_IMPLEMENTED) { return "Not Implemented"; }
    else if (status_code == HTTP_STATUS_BAD_GATEWAY) { return "Bad Gateway"; }
    else if (status_code == HTTP_STATUS_SERVICE_UNAVAILABLE) { return "Service Unavailable"; }
    else if (status_code == HTTP_STATUS_GATEWAY_TIMEOUT) { return "Gateway Time-out"; }
    else if (status_code == HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED) { return "HTTP Version not supported"; }
    else {
        errorf("unknown status code");
        return NULL;
    }
}