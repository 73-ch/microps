#ifndef HTTP_H
#define HTTP_H

#include <string.h>
#include "util.h"

#define HTTP_VERSION_1_0 10
#define HTTP_VERSION_1_1 11

#define HTTP_METHOD_GET 1
#define HTTP_METHOD_HEAD 2
#define HTTP_METHOD_POST 3
#define HTTP_METHOD_PUT 4
#define HTTP_METHOD_DELETE 5
#define HTTP_METHOD_CONNECT 6
#define HTTP_METHOD_OPTIONS 7
#define HTTP_METHOD_TRACE 8
#define HTTP_METHOD_PATCH 9

#define HTTP_STATUS_CONTINUE 100
#define HTTP_STATUS_SWITCHING_PROTOCOLS 101
#define HTTP_STATUS_OK 200
#define HTTP_STATUS_CREATED 201
#define HTTP_STATUS_ACCEPTED 202
#define HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION 203
#define HTTP_STATUS_NO_CONTENT 204
#define HTTP_STATUS_RESET_CONTENT 205
#define HTTP_STATUS_PARTIAL_CONTENT 206
#define HTTP_STATUS_MULTIPLE_CHOICES 300
#define HTTP_STATUS_MOVED_PERMANENTLY 301
#define HTTP_STATUS_FOUND 302
#define HTTP_STATUS_SEE_OTHER 303
#define HTTP_STATUS_NOT_MODIFIED 304
#define HTTP_STATUS_USE_PROXY 305
#define HTTP_STATUS_TEMPORARY_REDIRECT 307
#define HTTP_STATUS_BAD_REQUEST 400
#define HTTP_STATUS_UNAUTHORIZED 401
#define HTTP_STATUS_PAYMENT_REQUIRED 402
#define HTTP_STATUS_FORBIDDEN 403
#define HTTP_STATUS_NOT_FOUND 404
#define HTTP_STATUS_METHOD_NOT_ALLOWED 405
#define HTTP_STATUS_NOT_ACCEPTABLE 406
#define HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED 407
#define HTTP_STATUS_REQUEST_TIMEOUT 408
#define HTTP_STATUS_CONFLICT 409
#define HTTP_STATUS_GONE 410
#define HTTP_STATUS_LENGTH_REQUIRED 411
#define HTTP_STATUS_PRECONDITION_FAILED 412
#define HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE 413
#define HTTP_STATUS_REQUEST_URI_TOO_LARGE 414
#define HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE 415
#define HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE 416
#define HTTP_STATUS_EXPECTATION_FAILED 418
#define HTTP_STATUS_INTERNAL_SERVER_ERROR 500
#define HTTP_STATUS_NOT_IMPLEMENTED 501
#define HTTP_STATUS_BAD_GATEWAY 502
#define HTTP_STATUS_SERVICE_UNAVAILABLE 503
#define HTTP_STATUS_GATEWAY_TIMEOUT 504
#define HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED 505

extern char *http_status_text(int status_code);

extern char *http_method_name(int http_method);

extern int parse_http_method(char *method);

extern int parse_http_version(char *version_string);

extern char *http_version_name(int http_version);

#define HTTP_HEADER_NAME_MAX 256
#define HTTP_HEADER_VALUE_MAX 4096

struct http_header {
    char name[HTTP_HEADER_NAME_MAX];
    char value[HTTP_HEADER_VALUE_MAX];
};

struct http_header_list {
    struct http_header header;
    struct http_header_list *next;
};

struct http_request {
    int method;
    char *target;
    int version;
    struct http_header_list *header_list;
    char *body;
};

extern int parse_http_message(char* request_buffer, struct http_request* request);

int header_to_text(struct http_header_list* header_list, char* buf);

extern int create_response_message(char *buf, int status_code, struct http_header *header, char *body);

#endif //HTTP_H
