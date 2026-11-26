import 'dart:async';

import 'package:flutter/foundation.dart';

import 'api.dart';
import 'models.dart';

/// Holds the live dashboard state: overview from the SSE stream (every second), the
/// connection list (polled), and the live log (pushed per event). Reconnects on failure.
class DashboardController extends ChangeNotifier {
  DashboardController(this._api);
  final ApiClient? _api;

  Overview? overview;
  List<Connection> connections = const [];
  final List<LogEntry> log = [];
  static const maxLog = 1000;
  bool connected = false;
  String? error;
  bool logPaused = false;
  final List<LogEntry> _pausedBacklog = [];
  final List<double> throughput = []; // bytes/s samples for the sparkline
  int? _lastBytes;
  DateTime? _lastAt;

  StreamSubscription<(String, Json)>? _sub;
  Timer? _poll, _retry;
  bool _disposed = false;

  void start() {
    _connect();
    _poll = Timer.periodic(const Duration(seconds: 2), (_) => _refreshConnections());
  }

  Future<void> _connect() async {
    final api = _api;
    if (api == null || _disposed) return;
    await _sub?.cancel();
    try {
      _sub = api.stream().listen(
        (e) {
          final (type, data) = e;
          if (type == 'overview') {
            applyOverview(Overview.from(data));
          } else if (type == 'log') {
            addLog(LogEntry.from(data));
          }
        },
        onError: (Object err) => _fail(err),
        onDone: () => _fail('The API closed the stream'),
        cancelOnError: true,
      );
      unawaited(_refreshConnections());
    } catch (err) {
      _fail(err);
    }
  }

  void _fail(Object err) {
    if (_disposed) return;
    connected = false;
    error = err.toString();
    notifyListeners();
    _retry?.cancel();
    _retry = Timer(const Duration(seconds: 3), _connect);
  }

  Future<void> _refreshConnections() async {
    final api = _api;
    if (api == null || !connected) return;
    try {
      connections = await api.connections();
      if (!_disposed) notifyListeners();
    } catch (_) {
      // The stream reports connectivity; a failed poll just keeps the last list.
    }
  }

  @visibleForTesting
  void applyOverview(Overview o) {
    final now = o.generatedAt;
    final last = _lastBytes, at = _lastAt;
    if (last != null && at != null && o.engine.bytesSeen >= last) {
      final secs = now.difference(at).inMilliseconds / 1000;
      if (secs > 0) throughput.add((o.engine.bytesSeen - last) / secs);
      if (throughput.length > 120) throughput.removeAt(0);
    }
    _lastBytes = o.engine.bytesSeen;
    _lastAt = now;
    overview = o;
    connected = true;
    error = null;
    notifyListeners();
  }

  @visibleForTesting
  void addLog(LogEntry e) {
    if (logPaused) {
      _pausedBacklog.add(e);
      if (_pausedBacklog.length > maxLog) _pausedBacklog.removeAt(0);
      notifyListeners(); // keeps the Resume (N) count current
      return;
    }
    log.add(e);
    if (log.length > maxLog) log.removeRange(0, log.length - maxLog);
    notifyListeners();
  }

  @visibleForTesting
  void setConnections(List<Connection> c) {
    connections = c;
    notifyListeners();
  }

  int get pausedCount => _pausedBacklog.length;

  void toggleLogPause() {
    logPaused = !logPaused;
    if (!logPaused) {
      log.addAll(_pausedBacklog);
      _pausedBacklog.clear();
      if (log.length > maxLog) log.removeRange(0, log.length - maxLog);
    }
    notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _poll?.cancel();
    _retry?.cancel();
    unawaited(_sub?.cancel());
    _api?.close();
    super.dispose();
  }
}
