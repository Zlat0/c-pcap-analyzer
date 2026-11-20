#include "report/plot.h"

#include <math.h>
#include <stdio.h>

#include "report/format.h"

#define PA_FONT "DejaVu Sans"
#define PA_GRID_LINES 5
#define PA_MAX_BAR_LABELS 16

static const pa_rgb_t k_palette[] = {{0.12, 0.47, 0.71}, {1.00, 0.50, 0.05}, {0.17, 0.63, 0.17},
                                     {0.84, 0.15, 0.16}, {0.58, 0.40, 0.74}, {0.55, 0.34, 0.29}};

pa_rgb_t pa_plot_color(size_t i) { return k_palette[i % (sizeof k_palette / sizeof k_palette[0])]; }

double pa_plot_nice_max(double v) {
    double p, m;

    if (!(v > 0.0)) {
        return 1.0;
    }
    p = pow(10.0, floor(log10(v)));
    m = v / p;
    return (m <= 1.0 ? 1.0 : (m <= 2.0 ? 2.0 : (m <= 5.0 ? 5.0 : 10.0))) * p;
}

void pa_plot_text(cairo_t *cr, double x, double y, double size, int align, const char *s) {
    cairo_text_extents_t ext;

    cairo_set_font_size(cr, size);
    cairo_text_extents(cr, s, &ext);
    if (align == PA_ALIGN_CENTER) {
        x -= ext.width / 2.0;
    } else if (align == PA_ALIGN_RIGHT) {
        x -= ext.width;
    }
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, s);
}

static void set_color(cairo_t *cr, pa_rgb_t c) { cairo_set_source_rgb(cr, c.r, c.g, c.b); }

void pa_plot_begin(pa_plot_t *pl, cairo_t *cr, double w, double h, const char *title,
                   double left_margin) {
    pl->cr = cr;
    pl->w = w;
    pl->h = h;
    pl->left = left_margin;
    pl->right = w - 50.0;
    pl->top = 100.0;
    pl->bottom = h - 80.0;
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);
    cairo_select_font_face(cr, PA_FONT, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_source_rgb(cr, 0.1, 0.1, 0.1);
    pa_plot_text(cr, w / 2.0, 50.0, 28.0, PA_ALIGN_CENTER, title);
    cairo_select_font_face(cr, PA_FONT, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
}

void pa_plot_nodata(const pa_plot_t *pl) {
    cairo_set_source_rgb(pl->cr, 0.5, 0.5, 0.5);
    pa_plot_text(pl->cr, (pl->left + pl->right) / 2.0, (pl->top + pl->bottom) / 2.0, 26.0,
                 PA_ALIGN_CENTER, "no data");
}

void pa_plot_yaxis(const pa_plot_t *pl, double ymax, const char *ylabel) {
    cairo_t *cr = pl->cr;
    char buf[32];

    cairo_set_line_width(cr, 1.0);
    for (int i = 0; i <= PA_GRID_LINES; i++) {
        double y = pl->bottom - (pl->bottom - pl->top) * i / PA_GRID_LINES;

        cairo_set_source_rgb(cr, 0.85, 0.85, 0.85);
        cairo_move_to(cr, pl->left, y);
        cairo_line_to(cr, pl->right, y);
        cairo_stroke(cr);
        pa_format_si(ymax * i / PA_GRID_LINES, buf, sizeof buf);
        cairo_set_source_rgb(cr, 0.25, 0.25, 0.25);
        pa_plot_text(cr, pl->left - 10.0, y + 5.0, 14.0, PA_ALIGN_RIGHT, buf);
    }
    if (ylabel) {
        pa_plot_text(cr, pl->left, pl->top - 18.0, 15.0, PA_ALIGN_LEFT, ylabel);
    }
}

void pa_plot_xticks(const pa_plot_t *pl, double x0, double x1, const char *unit) {
    char buf[48], v[32];

    cairo_set_source_rgb(pl->cr, 0.25, 0.25, 0.25);
    for (int i = 0; i <= PA_GRID_LINES; i++) {
        double x = pl->left + (pl->right - pl->left) * i / PA_GRID_LINES;

        pa_format_si(x0 + (x1 - x0) * i / PA_GRID_LINES, v, sizeof v);
        snprintf(buf, sizeof buf, "%s %s", v, unit);
        pa_plot_text(pl->cr, x, pl->bottom + 26.0, 14.0, PA_ALIGN_CENTER, buf);
    }
}

void pa_plot_legend(const pa_plot_t *pl, const char *const *names, size_t n) {
    double x = pl->right - 150.0 * (double)n;

    for (size_t i = 0; i < n; i++, x += 150.0) {
        set_color(pl->cr, pa_plot_color(i));
        cairo_rectangle(pl->cr, x, pl->top - 38.0, 14.0, 14.0);
        cairo_fill(pl->cr);
        cairo_set_source_rgb(pl->cr, 0.2, 0.2, 0.2);
        pa_plot_text(pl->cr, x + 20.0, pl->top - 26.0, 15.0, PA_ALIGN_LEFT, names[i]);
    }
}

void pa_plot_bars(const pa_plot_t *pl, const char *const *labels, size_t n,
                  const double *const *series, size_t ns, double ymax) {
    cairo_t *cr = pl->cr;
    double gw, bw;
    size_t stride = n > PA_MAX_BAR_LABELS ? (n + PA_MAX_BAR_LABELS - 1) / PA_MAX_BAR_LABELS : 1;

    if (n == 0 || ns == 0 || !(ymax > 0.0)) {
        pa_plot_nodata(pl);
        return;
    }
    gw = (pl->right - pl->left) / (double)n;
    bw = gw * 0.8 / (double)ns;
    for (size_t i = 0; i < n; i++) {
        for (size_t s = 0; s < ns; s++) {
            double v = series[s][i];
            double hgt = v > 0.0 ? v / ymax * (pl->bottom - pl->top) : 0.0;
            double x = pl->left + gw * (double)i + gw * 0.1 + bw * (double)s;

            set_color(cr, pa_plot_color(s));
            cairo_rectangle(cr, x, pl->bottom - hgt, bw, hgt);
            cairo_fill(cr);
        }
        if (i % stride == 0) {
            cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
            pa_plot_text(cr, pl->left + gw * ((double)i + 0.5), pl->bottom + 24.0, 14.0,
                         PA_ALIGN_CENTER, labels[i]);
        }
    }
}

void pa_plot_hbars_bytes(const pa_plot_t *pl, const char *const *labels, const double *vals,
                         size_t n) {
    cairo_t *cr = pl->cr;
    double vmax = 0.0, rh, bh;
    char buf[32];

    for (size_t i = 0; i < n; i++) {
        vmax = vals[i] > vmax ? vals[i] : vmax;
    }
    if (n == 0 || !(vmax > 0.0)) {
        pa_plot_nodata(pl);
        return;
    }
    rh = (pl->bottom - pl->top) / (double)n;
    bh = rh * 0.7;
    for (size_t i = 0; i < n; i++) {
        double y = pl->top + rh * (double)i + (rh - bh) / 2.0;
        double len = vals[i] / vmax * (pl->right - pl->left - 120.0);

        set_color(cr, pa_plot_color(0));
        cairo_rectangle(cr, pl->left, y, len, bh);
        cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        pa_plot_text(cr, pl->left - 10.0, y + bh / 2.0 + 5.0, 15.0, PA_ALIGN_RIGHT, labels[i]);
        pa_format_bytes(vals[i], buf, sizeof buf);
        pa_plot_text(cr, pl->left + len + 8.0, y + bh / 2.0 + 5.0, 14.0, PA_ALIGN_LEFT, buf);
    }
}

void pa_plot_lines(const pa_plot_t *pl, const double *const *series, size_t ns, size_t n,
                   double ymax) {
    cairo_t *cr = pl->cr;
    double step;

    if (n == 0 || ns == 0 || !(ymax > 0.0)) {
        pa_plot_nodata(pl);
        return;
    }
    step = n > 1 ? (pl->right - pl->left) / (double)(n - 1) : 0.0;
    cairo_set_line_width(cr, 2.0);
    for (size_t s = 0; s < ns; s++) {
        set_color(cr, pa_plot_color(s));
        for (size_t i = 0; i < n; i++) {
            double x = pl->left + step * (double)i;
            double y = pl->bottom - series[s][i] / ymax * (pl->bottom - pl->top);

            if (i == 0) {
                cairo_move_to(cr, x, y);
            } else {
                cairo_line_to(cr, x, y);
            }
        }
        cairo_stroke(cr);
        if (n == 1) {
            cairo_arc(cr, pl->left, pl->bottom - series[s][0] / ymax * (pl->bottom - pl->top),
                      4.0, 0.0, 6.2831853);
            cairo_fill(cr);
        }
    }
}
