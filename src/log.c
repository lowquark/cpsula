
#include <log.h>

#include <stdio.h>
#include <time.h>

static FILE * file;
static _Bool color_enabled;

static void get_timestr(char (*str)[10]) {
  time_t t = time(NULL);
  struct tm time_val;

#ifdef __MINGW32__
    localtime_s(&time_val, &t);
#else
    localtime_r(&t, &time_val);
#endif

  strftime(*str, 10, "%H:%M:%S ", &time_val);
}

void log_init(FILE * _file) {
  file = _file;

  // TODO: There might be a better way to check for this
  color_enabled = _file == stdout || _file == stderr;
}

void log_info(const char * fmt, ...) {
  va_list args;
  char timestr[10];

  if(file) {
    get_timestr(&timestr);

    fputs(timestr, file);

    va_start(args, fmt);
    vfprintf(file, fmt, args);
    va_end(args);

    fputs("\n", file);
  }
}

void log_warning(const char * fmt, ...) {
  va_list args;
  char timestr[10];

  if(file) {
    get_timestr(&timestr);

    if(color_enabled) {
      fputs("\x1b[33m", file);
    }
    fputs(timestr, file);
    fputs("WARNING: ", file);

    va_start(args, fmt);
    vfprintf(file, fmt, args);
    va_end(args);

    if(color_enabled) {
      fputs("\x1b[0m\n", file);
    } else {
      fputs("\n", file);
    }
  }
}

void log_error(const char * fmt, ...) {
  va_list args;
  char timestr[10];

  if(file) {
    get_timestr(&timestr);

    if(color_enabled) {
      fputs("\x1b[31m", file);
    }
    fputs(timestr, file);
    fputs("ERROR: ", file);

    va_start(args, fmt);
    vfprintf(file, fmt, args);
    va_end(args);

    if(color_enabled) {
      fputs("\x1b[0m\n", file);
    } else {
      fputs("\n", file);
    }
  }
}

