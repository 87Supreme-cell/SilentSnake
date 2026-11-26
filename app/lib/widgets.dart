import 'dart:math' as math;

// ignore: deprecated_member_use
import 'package:flutter/material.dart';

import 'models.dart';
import 'theme.dart';

/// Glassy gradient card with a hairline border and an optional header.
class GlassCard extends StatelessWidget {
  const GlassCard({
    super.key,
    this.title,
    this.trailing,
    required this.child,
    this.padding = 20,
    this.expand = false,
  });
  final String? title;

  /// Fill the available height (full-screen cards); the child gets the remaining space.
  final bool expand;
  final Widget? trailing;
  final Widget child;
  final double padding;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Palette.border),
        gradient: const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Palette.cardTop, Palette.cardBottom],
        ),
        boxShadow: const [BoxShadow(color: Color(0x66000000), blurRadius: 24, offset: Offset(0, 10))],
      ),
      padding: EdgeInsets.all(padding),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: expand ? MainAxisSize.max : MainAxisSize.min,
        children: [
          if (title != null) ...[
            Row(
              children: [
                Expanded(
                  child: Text(
                    title!,
                    style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600, color: Palette.text),
                  ),
                ),
                ?trailing,
              ],
            ),
            const SizedBox(height: 14),
          ],
          if (expand) Expanded(child: child) else child,
        ],
      ),
    );
  }
}

/// Small muted label over a large value.
class Stat extends StatelessWidget {
  const Stat(this.label, this.value, {super.key, this.color});
  final String label, value;
  final Color? color;
  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(label, style: const TextStyle(fontSize: 12, color: Palette.muted)),
      const SizedBox(height: 4),
      Text(
        value,
        style: TextStyle(fontSize: 20, fontWeight: FontWeight.w600, color: color ?? Palette.text),
      ),
    ],
  );
}

/// Pill that pairs a colour with an icon and a label (never colour alone).
class StatusPill extends StatelessWidget {
  const StatusPill({super.key, required this.label, required this.color, required this.icon});
  final String label;
  final Color color;
  final IconData icon;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
    decoration: BoxDecoration(
      color: color.withValues(alpha: 0.12),
      borderRadius: BorderRadius.circular(999),
      border: Border.all(color: color.withValues(alpha: 0.35)),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 14, color: color),
        const SizedBox(width: 6),
        Text(
          label,
          style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: color),
        ),
      ],
    ),
  );
}

/// Gradient ring for the risk meter: arc length = score, colour = risk band.
class RiskRing extends StatelessWidget {
  const RiskRing({super.key, required this.score, required this.color, this.size = 150});
  final int score;
  final Color color;
  final double size;
  @override
  Widget build(BuildContext context) => TweenAnimationBuilder<double>(
    tween: Tween(end: score / 100),
    duration: MediaQuery.of(context).disableAnimations ? Duration.zero : const Duration(milliseconds: 600),
    curve: Curves.easeOutCubic,
    builder: (_, v, _) => CustomPaint(size: Size.square(size), painter: _RingPainter(v, color)),
  );
}

class _RingPainter extends CustomPainter {
  _RingPainter(this.fraction, this.color);
  final double fraction;
  final Color color;
  @override
  void paint(Canvas canvas, Size size) {
    final c = size.center(Offset.zero);
    final r = size.width / 2 - 10;
    final rect = Rect.fromCircle(center: c, radius: r);
    canvas.drawCircle(
      c,
      r,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 12
        ..color = const Color(0x1FFFFFFF),
    );
    final sweep = math.max(0.02, fraction) * 2 * math.pi;
    final shader = SweepGradient(
      startAngle: -math.pi / 2,
      endAngle: 3 * math.pi / 2,
      colors: [Palette.accent, color, color],
      stops: const [0, 0.6, 1],
      transform: const GradientRotation(-math.pi / 2),
    ).createShader(rect);
    canvas.drawArc(
      rect,
      -math.pi / 2,
      sweep,
      false,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 14
        ..color = color.withValues(alpha: 0.35)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 8),
    );
    canvas.drawArc(
      rect,
      -math.pi / 2,
      sweep,
      false,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 12
        ..strokeCap = StrokeCap.round
        ..shader = shader,
    );
  }

  @override
  bool shouldRepaint(_RingPainter o) => o.fraction != fraction || o.color != color;
}

/// Glowing sparkline (hero card).
class Sparkline extends StatelessWidget {
  const Sparkline({super.key, required this.values, this.height = 90});
  final List<double> values;
  final double height;
  @override
  Widget build(BuildContext context) =>
      CustomPaint(size: Size(double.infinity, height), painter: _SparkPainter(values));
}

class _SparkPainter extends CustomPainter {
  _SparkPainter(this.v);
  final List<double> v;
  @override
  void paint(Canvas canvas, Size size) {
    if (v.length < 2) {
      final p = Paint()
        ..color = Palette.faint
        ..strokeWidth = 1.5;
      canvas.drawLine(Offset(0, size.height - 4), Offset(size.width, size.height - 4), p);
      return;
    }
    final maxV = v.reduce(math.max).clamp(1, double.infinity);
    final dx = size.width / (v.length - 1);
    Offset at(int i) => Offset(i * dx, size.height - 6 - (v[i] / maxV) * (size.height - 16));
    final path = Path()..moveTo(at(0).dx, at(0).dy);
    for (var i = 1; i < v.length; i++) {
      final a = at(i - 1), b = at(i);
      final mid = (a.dx + b.dx) / 2;
      path.cubicTo(mid, a.dy, mid, b.dy, b.dx, b.dy);
    }
    final fill = Path.from(path)
      ..lineTo(size.width, size.height)
      ..lineTo(0, size.height)
      ..close();
    canvas.drawPath(
      fill,
      Paint()
        ..shader = LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [Palette.accent.withValues(alpha: 0.28), Palette.accent.withValues(alpha: 0)],
        ).createShader(Offset.zero & size),
    );
    canvas.drawPath(
      path,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 6
        ..color = Palette.accentGlow.withValues(alpha: 0.25)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 6),
    );
    canvas.drawPath(
      path,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2
        ..shader = const LinearGradient(colors: [Palette.accent, Palette.accentGlow, Palette.violet])
            .createShader(Offset.zero & size),
    );
    final last = at(v.length - 1);
    canvas.drawCircle(last, 7, Paint()..color = Palette.accentGlow.withValues(alpha: 0.25));
    canvas.drawCircle(last, 3.5, Paint()..color = Palette.accentGlow);
  }

  @override
  bool shouldRepaint(_SparkPainter o) => true;
}

/// Vertical glowing bars (traffic per minute). Highlights the busiest bar with its value.
class BarChart extends StatelessWidget {
  const BarChart({super.key, required this.buckets, this.height = 170});
  final List<Bucket> buckets;
  final double height;
  @override
  Widget build(BuildContext context) => CustomPaint(
    size: Size(double.infinity, height),
    painter: _BarPainter(buckets, DefaultTextStyle.of(context).style.fontFamily),
  );
}

class _BarPainter extends CustomPainter {
  _BarPainter(this.b, this.font);
  final List<Bucket> b;
  final String? font;

  void _text(Canvas c, String s, Offset center, double size, Color color, {bool bold = false}) {
    final tp = TextPainter(
      text: TextSpan(
        text: s,
        style: TextStyle(
          fontSize: size,
          color: color,
          fontFamily: font,
          fontWeight: bold ? FontWeight.w600 : null,
        ),
      ),
      textDirection: TextDirection.ltr,
    )..layout();
    tp.paint(c, center - Offset(tp.width / 2, tp.height / 2));
  }

  @override
  void paint(Canvas canvas, Size size) {
    const labelH = 18.0, topPad = 30.0;
    final n = math.max(b.length, 12);
    final slot = size.width / n;
    final barW = math.min(10.0, slot * 0.45);
    final chartH = size.height - labelH - topPad;
    final maxB = b.isEmpty ? 1 : b.map((e) => e.bytes).reduce(math.max).clamp(1, 1 << 62);
    final busiest = b.isEmpty ? -1 : b.indexWhere((e) => e.bytes == maxB);
    for (var i = 0; i < n; i++) {
      final x = i * slot + slot / 2;
      final track = RRect.fromRectAndRadius(
        Rect.fromLTWH(x - barW / 2, topPad, barW, chartH),
        Radius.circular(barW / 2),
      );
      canvas.drawRRect(track, Paint()..color = const Color(0x0FFFFFFF));
      final idx = i - (n - b.length);
      if (idx < 0) continue;
      final h = math.max(barW, chartH * b[idx].bytes / maxB);
      final rect = RRect.fromRectAndRadius(
        Rect.fromLTWH(x - barW / 2, topPad + chartH - h, barW, h),
        Radius.circular(barW / 2),
      );
      if (idx == busiest) {
        canvas.drawRRect(
          rect,
          Paint()
            ..color = Palette.accentGlow.withValues(alpha: 0.4)
            ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 8),
        );
      }
      canvas.drawRRect(
        rect,
        Paint()
          ..shader = const LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Palette.accentGlow, Palette.accent],
          ).createShader(rect.outerRect),
      );
      if (idx == busiest && b[idx].bytes > 0) {
        final label = formatBytes(b[idx].bytes);
        final y = topPad + chartH - h - 14;
        final bg = RRect.fromRectAndRadius(
          Rect.fromCenter(center: Offset(x, y), width: 10.0 + label.length * 6.5, height: 20),
          const Radius.circular(6),
        );
        canvas.drawRRect(bg, Paint()..color = const Color(0xFF1B2640));
        _text(canvas, label, Offset(x, y), 11, Palette.text, bold: true);
      }
      if (idx == 0 || idx == b.length - 1 || (b.length > 6 && idx == b.length ~/ 2)) {
        _text(canvas, hhmm(b[idx].minute), Offset(x, size.height - labelH / 2), 10, Palette.muted);
      }
    }
  }

  @override
  bool shouldRepaint(_BarPainter o) => true;
}

/// Horizontal bar row: label, bar, value.
class HBar extends StatelessWidget {
  const HBar({super.key, required this.label, required this.value, required this.fraction, this.color});
  final String label, value;
  final double fraction;
  final Color? color;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 6),
    child: Row(
      children: [
        SizedBox(
          width: 150,
          child: Text(
            label,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(fontSize: 13, color: Palette.text),
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: fraction.clamp(0, 1),
              minHeight: 6,
              backgroundColor: const Color(0x14FFFFFF),
              valueColor: AlwaysStoppedAnimation(color ?? Palette.accent),
            ),
          ),
        ),
        const SizedBox(width: 10),
        SizedBox(
          width: 70,
          child: Text(
            value,
            textAlign: TextAlign.right,
            style: const TextStyle(fontSize: 12, color: Palette.muted),
          ),
        ),
      ],
    ),
  );
}
