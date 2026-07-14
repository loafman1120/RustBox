import 'dart:async';

import 'package:flutter/material.dart';
import 'package:rustbox_flutter/rustbox_flutter.dart';

Future<void> main() async {
  await RustBox.initialize();
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  RustBoxEngine? _engine;
  String _status = 'Starting RustBox…';

  @override
  void initState() {
    super.initState();
    unawaited(_start());
  }

  Future<void> _start() async {
    try {
      final engine = await RustBoxEngine.create(configToml: _config);
      await engine.start();
      final snapshot = await engine.snapshot();
      _engine = engine;
      if (mounted) {
        setState(() {
          _status =
              'RustBox ${snapshot.state.name}: '
              '${snapshot.inboundCount} inbound, '
              '${snapshot.outboundCount} outbound';
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() => _status = error.toString());
      }
    }
  }

  @override
  void dispose() {
    final engine = _engine;
    if (engine != null) {
      unawaited(engine.close());
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('RustBox Flutter')),
        body: Center(child: Text(_status)),
      ),
    );
  }
}

const _config = '''
schema_version = 1

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:18080"

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "default"
outbound = "direct"
''';
