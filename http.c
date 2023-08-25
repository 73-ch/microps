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