// ignore: deprecated_member_use
import 'package:flutter/material.dart';

import 'api.dart';
import 'controller.dart';
import 'dashboard.dart';
import 'screens.dart';
import 'theme.dart';

/// `silentsnake [--page dashboard|connections|log]` opens on that page.
void main(List<String> args) {
  final i = args.indexOf('--page');
  final page = i >= 0 && i + 1 < args.length ? const {'connections': 1, 'log': 2}[args[i + 1]] ?? 0 : 0;
  runApp(SilentSnakeApp(controller: DashboardController(ApiClient())..start(), initialPage: page));
}

class SilentSnakeApp extends StatelessWidget {
  const SilentSnakeApp({super.key, required this.controller, this.initialPage = 0});
  final DashboardController controller;
  final int initialPage;
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'SilentSnake',
    debugShowCheckedModeBanner: false,
    theme: buildTheme(),
    home: Shell(c: controller, initialPage: initialPage),
  );
}

/// Left icon sidebar + content (design.style.layout).
class Shell extends StatefulWidget {
  const Shell({super.key, required this.c, this.initialPage = 0});
  final DashboardController c;
  final int initialPage;
  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> {
  late int page = widget.initialPage;
  static const _items = [
    (Icons.dashboard_rounded, 'Dashboard'),
    (Icons.lan_outlined, 'Connections'),
    (Icons.receipt_long_rounded, 'Live log'),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          const Positioned.fill(child: _Ambient()),
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  ListenableBuilder(
                    listenable: widget.c,
                    builder: (_, _) => _Sidebar(
                      selected: page,
                      items: _items,
                      onSelect: (i) => setState(() => page = i),
                      connected: widget.c.connected,
                    ),
                  ),
                  const SizedBox(width: 20),
                  Expanded(
                    child: ListenableBuilder(
                      listenable: widget.c,
                      builder: (_, _) => switch (page) {
                        1 => ConnectionsScreen(c: widget.c),
                        2 => LiveLogScreen(c: widget.c),
                        _ => DashboardScreen(c: widget.c),
                      },
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _Sidebar extends StatelessWidget {
  const _Sidebar({
    required this.selected,
    required this.items,
    required this.onSelect,
    required this.connected,
  });
  final int selected;
  final List<(IconData, String)> items;
  final ValueChanged<int> onSelect;
  final bool connected;
  @override
  Widget build(BuildContext context) => Container(
    width: 68,
    padding: const EdgeInsets.symmetric(vertical: 18),
    decoration: BoxDecoration(
      borderRadius: BorderRadius.circular(20),
      border: Border.all(color: Palette.border),
      color: const Color(0xCC0B1222),
    ),
    child: Column(
      children: [
        const _Logo(),
        const SizedBox(height: 26),
        for (var i = 0; i < items.length; i++)
          Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: Tooltip(
              message: items[i].$2,
              child: InkWell(
                borderRadius: BorderRadius.circular(12),
                onTap: () => onSelect(i),
                child: Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    color: i == selected ? Palette.accent.withValues(alpha: 0.18) : null,
                    border: i == selected ? Border.all(color: Palette.accent.withValues(alpha: 0.5)) : null,
                  ),
                  child: Icon(
                    items[i].$1,
                    size: 22,
                    color: i == selected ? Palette.accentGlow : Palette.muted,
                    semanticLabel: items[i].$2,
                  ),
                ),
              ),
            ),
          ),
        const Spacer(),
        Tooltip(
          message: connected ? 'Connected to 127.0.0.1:8765' : 'Not connected to the API',
          child: Icon(
            connected ? Icons.link_rounded : Icons.link_off_rounded,
            color: connected ? Palette.green : Palette.orange,
            size: 20,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          connected ? 'Live' : 'Offline',
          style: TextStyle(fontSize: 10, color: connected ? Palette.green : Palette.orange),
        ),
      ],
    ),
  );
}

/// Original mark: a radar sweep inside a ring.
class _Logo extends StatelessWidget {
  const _Logo();
  @override
  Widget build(BuildContext context) => Container(
    width: 40,
    height: 40,
    decoration: BoxDecoration(
      shape: BoxShape.circle,
      gradient: const SweepGradient(colors: [Palette.accent, Palette.violet, Palette.accent]),
      boxShadow: [BoxShadow(color: Palette.accent.withValues(alpha: 0.45), blurRadius: 16)],
    ),
    child: const Icon(Icons.radar_rounded, color: Colors.white, size: 24),
  );
}

/// Ambient background glows (blue top-right, ember bottom-right), as in the style reference.
class _Ambient extends StatelessWidget {
  const _Ambient();
  @override
  Widget build(BuildContext context) => const DecoratedBox(
    decoration: BoxDecoration(color: Palette.bg),
    child: Stack(
      children: [
        Positioned(right: -200, top: -220, child: _Glow(Palette.accent, 620, 0.22)),
        Positioned(right: -260, bottom: -160, child: _Glow(Palette.ember, 620, 0.20)),
        Positioned(left: 200, bottom: -300, child: _Glow(Palette.violet, 520, 0.10)),
      ],
    ),
  );
}

class _Glow extends StatelessWidget {
  const _Glow(this.color, this.size, this.alpha);
  final Color color;
  final double size, alpha;
  @override
  Widget build(BuildContext context) => Container(
    width: size,
    height: size,
    decoration: BoxDecoration(
      shape: BoxShape.circle,
      gradient: RadialGradient(
        colors: [
          color.withValues(alpha: alpha),
          color.withValues(alpha: 0),
        ],
      ),
    ),
  );
}
