"""Bounded, timestamp-based chart geometry; drawing uses only observed samples."""

import math


def scale_ceiling(peak):
    target = max(1.0, peak * 1.15)
    magnitude = 10 ** math.floor(math.log10(target))
    return next(step * magnitude for step in (1, 2, 5, 10) if step * magnitude >= target)


def geometry(values, times, width, height, interval=0.5):
    values = [v if v is not None and math.isfinite(v) and v >= 0 else None for v in values]
    peak = max((v for v in values if v is not None), default=0)
    ceiling = scale_ceiling(peak)
    if len(times) != len(values) or any(b < a for a, b in zip(times, times[1:])):
        times = [i * interval for i in range(len(values))]
    span = max(interval, times[-1] - times[0]) if times else interval
    latest = times[-1] if times else 0
    left, top, right, bottom = 54, 18, max(54, width - 18), max(18, height - 30)
    points = [
        None if value is None else (
            left + (stamp - latest + span) / span * (right - left),
            bottom - value / ceiling * (bottom - top),
        )
        for stamp, value in zip(times, values)
    ]
    return (left, top, right, bottom), ceiling, span, points


def draw(cr, width, height, values, times, interval, foreground=(0.2, 0.23, 0.26)):
    bounds, ceiling, span, points = geometry(values, times, width, height, interval)
    left, top, right, bottom = bounds
    if right <= left or bottom <= top:
        return
    cr.save()
    cr.set_font_size(10)
    cr.set_line_width(1)
    for fraction in (0, 0.5, 1):
        y = bottom - fraction * (bottom - top)
        cr.set_source_rgba(*foreground, 0.12)
        cr.move_to(left, y + 0.5)
        cr.line_to(right, y + 0.5)
        cr.stroke()
        cr.set_source_rgba(*foreground, 0.7)
        caption = f"{ceiling * fraction:,.3g}"
        cr.move_to(left - 10 - cr.text_extents(caption)[2], y + 3)
        cr.show_text(caption)
    for fraction in (0, 0.5, 1):
        x = left + fraction * (right - left)
        cr.set_source_rgba(*foreground, 0.08)
        cr.move_to(x, top)
        cr.line_to(x, bottom)
        cr.stroke()
        seconds = span * (1 - fraction)
        caption = "Latest" if not seconds else f"{seconds:.1f} s ago"
        text_width = cr.text_extents(caption)[2]
        offset = text_width if fraction == 1 else text_width / 2 if fraction else 0
        cr.set_source_rgba(*foreground, 0.7)
        cr.move_to(x - offset, bottom + 20)
        cr.show_text(caption)
    segments, segment = [], []
    for point in points:
        if point is None:
            if segment:
                segments.append(segment)
            segment = []
        else:
            segment.append(point)
    if segment:
        segments.append(segment)
    for segment in segments:
        cr.move_to(segment[0][0], bottom)
        for x, y in segment:
            cr.line_to(x, y)
        cr.line_to(segment[-1][0], bottom)
        cr.close_path()
        cr.set_source_rgba(0.16, 0.49, 0.86, 0.12)
        cr.fill()
        cr.move_to(*segment[0])
        for point in segment[1:]:
            cr.line_to(*point)
        cr.set_source_rgba(0.16, 0.49, 0.86, 0.95)
        cr.set_line_width(2)
        cr.stroke()
    if points and points[-1] is not None:
        cr.arc(*points[-1], 3, 0, math.tau)
        cr.fill()
    if not segments:
        caption = "Waiting for rate samples"
        cr.set_source_rgba(*foreground, 0.55)
        cr.move_to((left + right - cr.text_extents(caption)[2]) / 2, (top + bottom) / 2)
        cr.show_text(caption)
    cr.restore()
