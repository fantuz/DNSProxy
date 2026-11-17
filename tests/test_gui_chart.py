"""Chart scale, elapsed-time mapping and CLI sampling limits without a display."""

from contextlib import redirect_stderr
import importlib.util
import io
import math
import os
from pathlib import Path
import sys
import unittest

SOURCE = Path(
    os.environ.get(
        "DNSP_GUI_SOURCE", Path(__file__).resolve().parents[1] / "tools/linux-gui"
    )
)
sys.path.insert(0, str(SOURCE))
from chart import draw, geometry, scale_ceiling  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "gui_chart_options", SOURCE / "dnsp-gui.py"
)
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)


class ChartTests(unittest.TestCase):
    def test_startup_uses_the_canvas_and_actual_elapsed_time(self):
        bounds, ceiling, span, points = geometry([2, 4, 8], [10, 11, 14], 800, 180)
        left, top, right, bottom = bounds
        self.assertEqual(span, 4)
        self.assertEqual(points[0][0], left)
        self.assertEqual(points[-1][0], right)
        self.assertAlmostEqual(points[1][0], left + (right - left) / 4)
        self.assertGreater(ceiling, 8)
        self.assertTrue(all(top <= y <= bottom for _, y in points))

    def test_missing_and_invalid_values_are_gaps(self):
        _, _, _, points = geometry(
            [1, None, math.nan, -1, math.inf, 2], list(range(6)), 800, 180
        )
        self.assertTrue(all(point is None for point in points[1:5]))
        self.assertIsNotNone(points[-1])
        self.assertGreater(scale_ceiling(0), 0)

    def test_single_sample_is_visible_at_the_latest_edge(self):
        bounds, _, span, points = geometry([4], [10], 800, 180, 0.25)
        self.assertEqual(points[0][0], bounds[2])
        self.assertEqual(span, 0.25)

    def test_cairo_draws_empty_compact_and_gapped_charts(self):
        import cairo

        for width, height in ((700, 160), (1000, 220), (40, 20)):
            for values in ([], [3], [1, 2, None, 4, 2]):
                surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, width, height)
                draw(
                    cairo.Context(surface),
                    width,
                    height,
                    values,
                    list(range(len(values))),
                    0.5,
                )
                surface.flush()

    def test_faster_refresh_limits_and_default(self):
        self.assertEqual(gui.arguments([]).interval, 0.5)
        self.assertEqual(gui.arguments(["--interval", "0.25"]).interval, 0.25)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            gui.arguments(["--interval", "0.1"])


if __name__ == "__main__":
    unittest.main()
