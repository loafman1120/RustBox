Pod::Spec.new do |s|
  s.name             = 'rustbox_flutter'
  s.version          = '0.1.0'
  s.summary          = 'Flutter FFI bindings for the RustBox proxy runtime.'
  s.description      = 'Precompiled RustBox runtime bindings for Flutter applications.'
  s.homepage         = 'https://github.com/loafman1120/RustBox'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Jun Kang' => 'loafman1120@users.noreply.github.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.vendored_libraries = '../native/macos/librustbox_flutter_bridge.a'
  s.dependency 'FlutterMacOS'
  s.platform = :osx, '11.0'
  s.swift_version = '5.0'
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES'
  }
  s.user_target_xcconfig = {
    'OTHER_LDFLAGS' => '$(inherited) -all_load'
  }
end
