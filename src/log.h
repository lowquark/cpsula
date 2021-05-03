#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdio.h>

void log_init(FILE * file);

void log_info(const char * fmt, ...) __attribute__((format (printf, 1, 2)));
void log_warning(const char * fmt, ...) __attribute__((format (printf, 1, 2)));
void log_error(const char * fmt, ...) __attribute__((format (printf, 1, 2)));

#endif
