#include "http.h"
#include "util.h"
#include "platform.h"

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

void print_http_header_list(struct http_header_list* header_list) {
    struct http_header_list* tmp_header = header_list;
    while (tmp_header != NULL) {
        infof("header: %s: %s", tmp_header->header.name, tmp_header->header.value);
        tmp_header  = tmp_header->next;
    }
}

 int parse_http_message(char* request_buffer, struct http_request* request) {
    // リクエストメッセージのパース
    char *start_line;
    char *header_message;
    char *body_message;

    start_line = request_buffer;
    char *start_line_end = strstr(request_buffer, "\r\n");
    *start_line_end = '\0';

    header_message = start_line_end + strlen("\r\n");
    char *header_message_end= strstr(header_message, "\r\n\r\n");
    if (header_message_end) {
        *header_message_end = '\0';
    }

    body_message = header_message_end + strlen("\r\n\r\n");

    // 開始行のパース
    char *tmp_method;
    char *tmp_target;
    char *header_parse_restart = NULL;
    /* method */
    tmp_method = strtok(start_line, " ");
    if (tmp_method == NULL) {
        errorf("parse method error");
        return HTTP_STATUS_BAD_REQUEST;
    }
    int method;
    method = parse_http_method(tmp_method);
    if (method < 0) {
        errorf("unknown parse error");
        return HTTP_STATUS_NOT_IMPLEMENTED;
    }

    /* target */
    tmp_target = strtok(NULL, " ");
    if (tmp_target == NULL) {
        printf("get target error\n");
        return HTTP_STATUS_BAD_REQUEST;
    }

    /* http version */
    int http_version;
    char *tmp_http_version;
    tmp_http_version = strtok(NULL, " ");
    http_version = parse_http_version(tmp_http_version);
    if (http_version < 0) {
        errorf("http version not supported.");
        // 505 error
        return HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED;
    }

    // parse header
    char *tmp_header_line;
    struct http_header_list *header_list = NULL;

    char *tmp_header_name;
    char *tmp_header_value;

    tmp_header_line = strtok_r(header_message, "\r\n", &header_parse_restart);

    while (tmp_header_line != NULL) {
        struct http_header_list *new_header_list = memory_alloc(sizeof(struct new_header_list *));

        if (!new_header_list) {
            errorf("memory_alloc() failure");
            return HTTP_STATUS_INTERNAL_SERVER_ERROR;
        }

        tmp_header_name = strtok(tmp_header_line, ": ");
        tmp_header_value = strtok(NULL, "");

        if (strlen(tmp_header_name) > HTTP_HEADER_NAME_MAX || strlen(tmp_header_value) > HTTP_HEADER_VALUE_MAX) {
            return HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE;
        }

        strcpy(new_header_list->header.name, tmp_header_name);
        strcpy(new_header_list->header.value+1, tmp_header_value);
        if (header_list) {
            new_header_list->next = header_list;
        }

        header_list = new_header_list;

        tmp_header_line = strtok_r(NULL, "\r\n", &header_parse_restart);
    }


    // HTTP Requestの表示
    infof("HTTP Request: ");
    infof("method: %s, target: %s, version: %s", http_method_name(method), tmp_target, http_version_name(http_version));

    print_http_header_list(header_list);


    // check required header

    if (http_version >= HTTP_VERSION_1_1) {
        struct http_header_list* tmp_header_list;
        tmp_header_list = header_list;
        while (tmp_header_list != NULL) {
            if (strcmp(tmp_header_list->header.name, "Host") == 0) {
                break;
            }
            tmp_header_list = tmp_header_list->next;
        }

        if (tmp_header_list == NULL) {
            // bad request
            errorf("Host header is required.");
            return HTTP_STATUS_BAD_REQUEST;
        }
    }
     request->header_list = header_list;
     request->version = http_version;
     request->target = tmp_target;
     request->method = method;
     request->body = body_message;

     return HTTP_STATUS_OK;
}

int generate_status_line(int status_code, char* buf) {
    return sprintf(buf, "HTTP/%s %i %s\r\n", http_version_name(HTTP_VERSION_1_1), status_code, http_status_text(status_code));
}

int header_to_text(struct http_header_list *header_list, char* buf) {
    int len = 0;
    while (header_list != NULL) {
        int tmp_len = sprintf(&buf[len], "%s: %s\r\n", header_list->header.name, header_list->header.value);
        if (tmp_len < 0) {
            errorf("sprintf() failure");
            return -1;
        }
        len += tmp_len;
        header_list = header_list->next;
    }
    return len;
}

int create_response_message(char* buf, int status_code, struct http_header* header, char* body) {
    int status_line_len = generate_status_line(status_code, buf);
    if (status_line_len < 0) {
        errorf("generate_status_line() failure");
        return -1;
    }

    int header_len = 0;
    if (header) {
        header_len = header_to_text(header, &buf[status_line_len]);
        if (header_len < 0) {
            errorf("header_to_text() failure");
            return -1;
        }
        strcpy(&buf[status_line_len + header_len], "\r\n");
        header_len += 2;
    }

    if (body) {
        strcpy(&buf[status_line_len + header_len], body);
    } else {
        strcpy(&buf[status_line_len + header_len], "\r\n");
    }

    strcpy(&buf[status_line_len + header_len + strlen(body)], "\r\n");

    return status_line_len + header_len + strlen(body);
}