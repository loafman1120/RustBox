import 'package:integration_test/integration_test.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rustbox_flutter/rustbox_flutter.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(RustBox.initialize);

  test('completes the RustBox lifecycle', () async {
    final engine = await RustBoxEngine.create(configToml: _config);
    expect((await engine.snapshot()).state, RustBoxEngineState.prepared);
    await engine.start();
    expect((await engine.snapshot()).state, RustBoxEngineState.running);
    await engine.reload(_config);
    expect((await engine.snapshot()).generation, 1);
    await engine.stop();
    expect((await engine.snapshot()).state, RustBoxEngineState.stopped);
    await engine.close();
    await engine.close();
  });

  test('reports invalid configuration', () async {
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
