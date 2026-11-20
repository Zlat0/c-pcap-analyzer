#ifndef PA_REPORT_PLOT_H
#define PA_REPORT_PLOT_H

#include <cairo.h>
#include <stddef.h>

#define PA_ALIGN_LEFT 0
#define PA_ALIGN_CENTER 1
#define PA_ALIGN_RIGHT 2

typedef struct {
    double r, g, b;
} pa_rgb_t;

/* Plot area (left..right, top..bottom) inside a w x h canvas. */
typedef struct {
    cairo_t *cr;
    double w, h;
    double left, right, top, bottom;
} pa_plot_t;

pa_rgb_t pa_plot_color(size_t i);
/** Rounds v up to 1, 2 or 5 times a power of ten (axis maximum). */
double pa_plot_nice_max(double v);
void pa_plot_text(cairo_t *cr, double x, double y, double size, int align, const char *s);
/** Paints the white background and the title; left_margin leaves room for category labels. */
void pa_plot_begin(pa_plot_t *pl, cairo_t *cr, double w, double h, const char *title,
                   double left_margin);
void pa_plot_nodata(const pa_plot_t *pl);
void pa_plot_yaxis(const pa_plot_t *pl, double ymax, const char *ylabel);
void pa_plot_xticks(const pa_plot_t *pl, double x0, double x1, const char *unit);
void pa_plot_legend(const pa_plot_t *pl, const char *const *names, size_t n);
/** Vertical (grouped) bars: series[s][i] is the value of series s in category i. */
void pa_plot_bars(const pa_plot_t *pl, const char *const *labels, size_t n,
                  const double *const *series, size_t ns, double ymax);
/** Horizontal bars with the value printed as a byte size. */
void pa_plot_hbars_bytes(const pa_plot_t *pl, const char *const *labels, const double *vals,
                         size_t n);
void pa_plot_lines(const pa_plot_t *pl, const double *const *series, size_t ns, size_t n,
                   double ymax);

#endif
