#ifndef PA_CORE_LOG_H
#define PA_CORE_LOG_H

typedef enum { PA_LVL_ERROR = 0, PA_LVL_WARN, PA_LVL_INFO, PA_LVL_DEBUG } pa_log_level_t;

/** Sets the global verbosity (the only mutable global in the program). */
void pa_log_set_level(int level);
void pa_log_write(int level, const char *file, int line, const char *fmt, ...);

#define PA_LOG_ERROR(...) pa_log_write(PA_LVL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define PA_LOG_WARN(...) pa_log_write(PA_LVL_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define PA_LOG_INFO(...) pa_log_write(PA_LVL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define PA_LOG_DEBUG(...) pa_log_write(PA_LVL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#endif
