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

extern char * http_method_name(int http_method) ;

extern int parse_http_method(char *method);

extern int parse_http_version(char* version_string);

extern char * http_version_name(int http_version);

struct http_header {
    char* header_name;
    char* value;
    struct http_header *next;
};

#endif //HTTP_H
