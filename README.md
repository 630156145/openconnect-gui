# OpenConnect GUI

OpenConnect GUI development moved to [Gitlab OpenConnect GUI project](https://gitlab.com/openconnect/openconnect-gui).

## macOS 编译

依赖来自 Homebrew：CMake、`qt@5`、`openconnect`。`qt@5` 是 keg-only，配置时要写出它的路径。在仓库根目录执行。

`build-release` 已经配置过时，增量编译：

```bash
cmake --build build-release -j"$(sysctl -n hw.ncpu)"
/opt/homebrew/opt/qt@5/bin/macdeployqt build-release/bin/OpenConnect-GUI.app
codesign --force --deep --sign - build-release/bin/OpenConnect-GUI.app
```

第一次编译，或需要重新配置时：

```bash
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:${PKG_CONFIG_PATH}"
SDK="$(xcrun --show-sdk-path)"
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DCMAKE_PREFIX_PATH="/opt/homebrew;/opt/homebrew/opt/qt@5" \
  -DQt5_DIR="/opt/homebrew/opt/qt@5/lib/cmake/Qt5" \
  -DCMAKE_OSX_SYSROOT="$SDK" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0
cmake --build build-release -j"$(sysctl -n hw.ncpu)"
/opt/homebrew/opt/qt@5/bin/macdeployqt build-release/bin/OpenConnect-GUI.app
codesign --force --deep --sign - build-release/bin/OpenConnect-GUI.app
```

产物是 `build-release/bin/OpenConnect-GUI.app`。`macdeployqt` 把 Qt 打进 app，`codesign` 做本机临时签名。只跑 `cmake --build` 的话，可执行文件仍链接 Homebrew 里的 Qt，启动时会崩溃。




