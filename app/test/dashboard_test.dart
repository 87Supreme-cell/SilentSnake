// ignore: deprecated_member_use
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:silentsnake/controller.dart';
import 'package:silentsnake/main.dart';
import 'package:silentsnake/models.dart';

Overview sampleOverview({int score = 45, String level = 'guarded', bool running = true}) {
  final now = DateTime.now().toUtc();
  return Overview.from({
    'risk': {
      'score': score,
      'level': level,
      'color': 'yellow',
      'reasons': ['203.0.113.9: another machine opened this connection to you', 'Telnet is unencrypted'],
    },
    'engine': {
      'running': running,
      'interface': 'any',
      'version': '0.1.0',
      'started_at': now.subtract(const Duration(minutes: 12)).toIso8601String(),
      'packets_seen': 48211,
      'bytes_seen': 51234567,
      'flows_active': 37,
      'kernel_dropped': 0,
      'incomplete': false,
    },
    'active_flows': 37,
    'flagged_flows': 1,
    'traffic_per_minute': [
      for (var i = 0; i < 20; i++)
        {
          'minute': now.subtract(Duration(minutes: 19 - i)).toIso8601String(),
          'bytes': 200000 + (i * 73919) % 900000,
          'flows': 10 + i,
        },
    ],
    'top_destinations': [
      {'name': 'example.com', 'bytes': 9000000, 'flows': 12},
      {'name': 'updates.example.org', 'bytes': 4000000, 'flows': 3},
    ],
    'generated_at': now.toIso8601String(),
  });
}

List<Connection> sampleConnections() => [
  Connection.from({
    'flow_id': 2,
    'proto': 'tcp',
    'direction': 'inbound',
    'initiator': {'ip': '203.0.113.9', 'port': 40000},
    'responder': {'ip': '192.168.1.10', 'port': 23},
    'service': 'telnet',
    'risk': 55,
    'risk_reasons': ['another machine opened this connection to you', 'Telnet is unencrypted'],
    'status': 'flagged',
    'summary': 'Inbound telnet.',
  }),
  Connection.from({
    'flow_id': 3,
    'proto': 'tcp',
    'direction': 'outbound',
    'initiator': {'ip': '192.168.1.10', 'port': 50000},
    'responder': {'ip': '93.184.216.34', 'port': 443},
    'service': 'https',
    'server_name': 'example.com',
    'risk': 0,
    'status': 'allowed',
    'summary': 'Outbound HTTPS.',
  }),
];

DashboardController loadedController() {
  final c = DashboardController(null);
  c.applyOverview(sampleOverview());
  c.setConnections(sampleConnections());
  c.addLog(LogEntry(1, DateTime.now(), 'flow_start', 'New outbound HTTPS connection to example.com.'));
  c.addLog(LogEntry(2, DateTime.now(), 'dns', 'DNS answer: example.com is 93.184.216.34.'));
  return c;
}

Future<void> pumpApp(WidgetTester t, DashboardController c) async {
  t.view.physicalSize = const Size(1400, 1000);
  t.view.devicePixelRatio = 1;
  addTearDown(t.view.reset);
  await t.pumpWidget(SilentSnakeApp(controller: c));
  await t.pump(const Duration(seconds: 1));
}

void main() {
  testWidgets('dashboard shows risk with label, score and peers', (t) async {
    await pumpApp(t, loadedController());
    expect(find.text('45'), findsWidgets);
    expect(find.text('Guarded'), findsOneWidget); // label, not colour alone
    expect(find.text('Capturing'), findsOneWidget);
    expect(find.text('example.com'), findsWidgets);
    expect(find.text('Flagged'), findsWidgets);
    expect(find.text('203.0.113.9:40000'), findsWidgets); // inbound peer is the remote side
    expect(t.takeException(), isNull);
  });

  testWidgets('connections and live log screens render', (t) async {
    final c = loadedController();
    await pumpApp(t, c);
    await t.tap(find.byTooltip('Connections'));
    await t.pump(const Duration(milliseconds: 300));
    expect(find.text('Connections'), findsWidgets);
    await t.tap(find.text('Flagged only'));
    await t.pump();
    expect(find.text('example.com'), findsNothing);
    await t.tap(find.byTooltip('Live log'));
    await t.pump(const Duration(milliseconds: 300));
    expect(find.textContaining('DNS answer'), findsOneWidget);
    await t.tap(find.text('Pause'));
    await t.pump();
    c.addLog(LogEntry(3, DateTime.now(), 'dns', 'held while paused'));
    await t.pump();
    expect(find.textContaining('held while paused'), findsNothing);
    expect(find.textContaining('Resume (1)'), findsOneWidget);
    expect(t.takeException(), isNull);
  });

  testWidgets('disconnected and stopped states are explicit', (t) async {
    final c = DashboardController(null);
    await pumpApp(t, c);
    expect(find.textContaining('Connecting to the SilentSnake API'), findsOneWidget);
    expect(find.text('Offline'), findsOneWidget);
    c.applyOverview(sampleOverview(score: 0, level: 'low', running: false));
    await t.pump(const Duration(seconds: 1));
    expect(find.text('Stopped'), findsOneWidget);
    expect(find.text('Low'), findsOneWidget);
    expect(t.takeException(), isNull);
  });
}
