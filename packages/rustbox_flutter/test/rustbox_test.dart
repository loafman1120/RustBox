import 'package:flutter_test/flutter_test.dart';
import 'package:rustbox_flutter/rustbox_flutter.dart';

void main() {
  setUpAll(RustBox.initialize);

  test('initialization is idempotent', () async {
    await Future.wait([RustBox.initialize(), RustBox.initialize()]);
  });

  test('lifecycle futures return completed state', () async {
    final engine = await RustBoxEngine.create(configToml: _config);
    addTearDown(engine.close);

    expect((await engine.snapshot()).state, RustBoxEngineState.prepared);
    await engine.start();
    expect((await engine.snapshot()).state, RustBoxEngineState.running);

    await expectLater(
      engine.start(),
      throwsA(
        isA<RustBoxException>().having(
          (error) => error.kind,
          'kind',
          RustBoxExceptionKind.invalidState,
        ),
      ),
    );

    await engine.reload(_config);
    expect((await engine.snapshot()).generation, 1);
    await engine.stop();
    expect((await engine.snapshot()).state, RustBoxEngineState.stopped);
  });

  test('close is idempotent and rejects later calls', () async {
    final engine = await RustBoxEngine.create(configToml: _config);
    await engine.close();
    await engine.close();
    expect(
      engine.snapshot,
      throwsA(
        isA<RustBoxException>().having(
          (error) => error.kind,
          'kind',
          RustBoxExceptionKind.unavailable,
        ),
      ),
    );
  });

  test('invalid TOML is categorized', () async {
    await expectLater(
      RustBoxEngine.create(configToml: 'not toml'),
      throwsA(
        isA<RustBoxException>().having(
          (error) => error.kind,
          'kind',
          RustBoxExceptionKind.invalidConfig,
        ),
      ),
    );
  });
}

const _config = '''
schema_version = 1

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:0"

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "default"
outbound = "direct"
''';
