# Wasm𝟛𝟘

Wasm30 is the fork o the efficient wasm interpreter Wasm3, made by [**Volodymyr Shymanskyy**](https://github.com/vshymanskyy) 🇺🇦.

This new branded fork was born from the need to run wasm binaries on the limited resources of the ESP32. Given this, at the moment WASM30 can be heavily dependent on the ESP-IDF environment.

The first peculiarity of WASM30 compared to WASM3 is to have specialized the `M3Memory` class (in the file `m3_segmented_memory.c`) to support data segmentation and, consequently, segment paging with real-time storage and retrieval in case of need during runtime.

To have a practical implementation of WASM30 in a ESP32 architecture, take a look to the [HelloESP repo](https://github.com/cekkr/hello.esp32). In the repo are present also practical examples about how implement native functions in the WASM runtime in files `he_wasm.c` and `he_wasm_native.c`.

## Why WASM3 + 0?
A part the segmented memory support, WASM30 aims to implement the Memory64 specifications also inside 32 bit architectures. This complete fork is also necessary due to the heavy modification of the original code, that makes a merge to the original project impossible.

## Credits
Work in progress by Riccardo Cecchini ([cekkr](https://github.com/cekkr))

# Original WASM3 README

> [!NOTE]
> I regret to inform the community that since [my house was destroyed by russians who invaded my country](https://twitter.com/vshymanskyy/status/1568657607229075456), **Wasm3 will enter a minimal maintenance phase**. At this time, I am unable to continue the development of new features. However, I am committed to keeping the project alive and will actively review and merge incoming Pull Requests. I deeply appreciate your understanding and support during this difficult period. **Your contributions to Wasm3 are now more valuable than ever.**

<img align="right" width="30%" src="https://github.com/wasm3/wasm3/blob/main/extra/screenshot-ios.png?raw=true">

# <img src="https://raw.githubusercontent.com/wasm3/wasm3/79d412ea5fcf92f0efe658d52827a0e0a96ff442/extra/wasm-symbol.svg" width="32" height="32" /> Wasm3

[![StandWithUkraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md) 
[![GitHub issues](https://img.shields.io/github/issues-raw/wasm3/wasm3?style=flat-square&label=issues&color=success)](https://github.com/wasm3/wasm3/issues) 
[![Tests status](https://img.shields.io/github/actions/workflow/status/wasm3/wasm3/tests.yml?branch=main&style=flat-square&logo=github&label=tests)](https://github.com/wasm3/wasm3/actions) 
[![Fuzzing Status](https://img.shields.io/badge/oss--fuzz-fuzzing-success?style=flat-square)](https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=proj:wasm3) 
[![GitHub license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](https://github.com/wasm3/wasm3) 

A fast WebAssembly interpreter and the most universal WASM runtime.  
<sub>Based on [**CoreMark 1.0**](./docs/Performance.md) and [**independent**](https://00f.net/2021/02/22/webassembly-runtimes-benchmarks) benchmarks. Your mileage may vary.</sub>

[![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/wasm3_engine)](https://twitter.com/wasm3_engine) 
[![Discord](https://img.shields.io/discord/671415645073702925?style=social&logo=discord&color=7289da&label=discord)](https://discord.gg/qmZjgnd)

## Installation

**Please follow the [installation instructions](./docs/Installation.md).**

Wasm3 can also be used as a library for:

[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/python.svg" width="18" height="18" /> Python3](https://github.com/wasm3/pywasm3) │ 
[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/rust.svg" width="18" height="18" /> Rust](https://github.com/wasm3/wasm3-rs) │ 
[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/cplusplus.svg" width="18" height="18" /> C/C++](https://github.com/wasm3/wasm3) │ 
[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/d.svg" width="18" height="18" /> D](https://github.com/kassane/wasm3-d) │ 
[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/go.svg" width="18" height="18" /> GoLang](https://github.com/matiasinsaurralde/go-wasm3) │ 
[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/zig.svg" width="18" height="18" /> Zig](https://github.com/alichay/zig-wasm3) │
[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/perl.svg" width="18" height="18" /> Perl](https://metacpan.org/pod/Wasm::Wasm3)  
[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/swift.svg" width="18" height="18" /> Swift](https://github.com/shareup/wasm-interpreter-apple) │ 
[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/dotnet.svg" width="18" height="18" /> .Net](https://github.com/tana/Wasm3DotNet) │ 
[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/nim.svg" width="18" height="18" /> Nim](https://github.com/beef331/wasm3) │ 
[<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/arduino.svg" width="18" height="18" /> Arduino, PlatformIO, Particle](https://github.com/wasm3/wasm3-arduino) │ [QuickJS](https://github.com/saghul/txiki.js)

## Status

`wasm3` passes the [WebAssembly spec testsuite](https://github.com/WebAssembly/spec/tree/master/test/core) and is able to run many `WASI` apps.

Minimum useful system requirements: **~64Kb** for code and **~10Kb** RAM

`wasm3` runs on a wide range of architectures (`x86`, `x86_64`, `ARM`, `RISC-V`, `PowerPC`, `MIPS`, `Xtensa`, `ARC32`, ...) and [platforms](/platforms):
- <img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/linux.svg" width="18" height="18" /> Linux,
<img src="https://upload.wikimedia.org/wikipedia/commons/c/c4/Windows_logo_-_2021_%28Black%29.svg" width="18" height="18" /> Windows,
<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/apple.svg" width="18" height="18" /> OS X,
<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/freebsd.svg" width="18" height="18" /> FreeBSD,
<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/android.svg" width="18" height="18" /> Android,
<img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/apple.svg" width="18" height="18" /> iOS
- <img src="https://cdn.rawgit.com/feathericons/feather/master/icons/wifi.svg" width="18" height="18" /> OpenWrt, Yocto, Buildroot (routers, modems, etc.)
- <img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/raspberrypi.svg" width="18" height="18" /> Raspberry Pi, Orange Pi and other SBCs
- <img src="https://cdn.rawgit.com/feathericons/feather/master/icons/cpu.svg" width="18" height="18" /> MCUs: Arduino, ESP8266, ESP32, Particle, ... [see full list](./docs/Hardware.md)
- <img src="https://cdn.jsdelivr.net/gh/simple-icons/simple-icons@develop/icons/firefoxbrowser.svg" width="18" height="18" /> Browsers. Yes, using WebAssembly itself!
- <img src="extra/wasm-symbol.svg" width="18" height="18" /> `wasm3` can execute `wasm3` (self-hosting)

## Features

| Webassembly [Proposals][WasmProps]  | Extra |
| --- | --- |
| ☑ Import/Export of Mutable Globals           | ☑ Structured execution tracing     |
| ☑ Non-trapping float-to-int conversions      | ☑ Big-Endian systems support       |
| ☑ Sign-extension operators                   | ☑ Wasm and WASI self-hosting       |
| ☑ Multi-value                                | ☑ Gas metering                     |
| ☑ Bulk memory operations (partial support)   | ☑ Linear memory limit (< 64KiB)    |
| ☑ Custom page size                           |
| ⏳ Multiple memories                          |
| ⏳ Reference types                            |
| ☐ Tail call optimization                     |
| ☐ Fixed-width SIMD                           |
| ☐ Exception handling                         |
| ☐ Stack Switching                            |

## Motivation

**Why use a "slow interpreter" versus a "fast JIT"?**

In many situations, speed is not the main concern. Runtime executable size, memory usage, startup latency can be improved with the interpreter approach. Portability and security are much easier to achieve and maintain. Additionally, development impedance is much lower. A simple library like Wasm3 is easy to compile and integrate into an existing project. (Wasm3 builds in a just few seconds). Finally, on some platforms (i.e. iOS and WebAssembly itself) you can't generate executable code pages in runtime, so JIT is unavailable.

**Why would you want to run WASM on embedded devices?**

Wasm3 started as a research project and remains so by any means. Evaluating the engine in different environments is part of the research. Given that we have `Lua`, `JS`, `Python`, `Lisp`, `...` running on MCUs, `WebAssembly` is a promising alternative. It provides toolchain decoupling as well as a completely sandboxed, well-defined, predictable environment. Among practical use cases we can list `edge computing`, `scripting`, `plugin systems`, running `IoT rules`, `smart contracts`, etc.

## Used by

[<img src="https://raw.githubusercontent.com/wasm3/wasm3/79d412ea5fcf92f0efe658d52827a0e0a96ff442/extra/logos/wasmcloud.png" height="32" />](https://wasmcloud.dev)　
[<img src="https://raw.githubusercontent.com/wasm3/wasm3/79d412ea5fcf92f0efe658d52827a0e0a96ff442/extra/logos/wowcube.png" height="32" />](https://wowcube.com)　
[<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/3/3c/Siemens_AG_logo.svg/1024px-Siemens_AG_logo.svg.png" height="22" />](https://github.com/siemens/dtasm/tree/main/runtime/dtasm3)　
[<img src="https://raw.githubusercontent.com/wasm3/wasm3/79d412ea5fcf92f0efe658d52827a0e0a96ff442/extra/logos/scailable.png" height="32" />](https://scailable.net)　
[<img src="https://raw.githubusercontent.com/wasm3/wasm3/79d412ea5fcf92f0efe658d52827a0e0a96ff442/extra/logos/blynk.png" height="32" />](https://blynk.io)　
[<img src="https://raw.githubusercontent.com/wasm3/wasm3/79d412ea5fcf92f0efe658d52827a0e0a96ff442/extra/logos/iden3.svg" height="32" />](https://www.iden3.io)　
[<img src="https://upload.wikimedia.org/wikipedia/commons/b/b0/NuttX_logo.png" height="32" />](https://github.com/apache/incubator-nuttx-apps/tree/master/interpreters/wasm3)　
[<img src="https://raw.githubusercontent.com/wasm3/wasm3/79d412ea5fcf92f0efe658d52827a0e0a96ff442/extra/logos/losant.png" height="28" />](https://github.com/Losant/eea-examples)　
[<img src="https://user-images.githubusercontent.com/1506708/114701856-069ce700-9d2c-11eb-9b72-9ce2dfd9f0fb.png" height="32" />](https://github.com/kateinoigakukun/wasmic-ios)　
[<img src="https://assets-global.website-files.com/636ab6ba0e1bd250e3aaedaf/636e155e93894cd4d030c4d7_balena_logo_dark.svg" height="32" />](https://github.com/balena-io-playground/balena-wasm3)　
[<img src="https://krustlet.dev/images/horizontal.svg" height="32" />](https://github.com/deislabs/krustlet-wasm3)　
[<img src="https://raw.githubusercontent.com/wasm3/wasm3/79d412ea5fcf92f0efe658d52827a0e0a96ff442/extra/logos/shareup_app.svg" height="24" />](https://shareup.app/blog/introducing-shareup)　
[<img src="https://wasm4.org/img/logo.png" height="32" />](https://wasm4.org)

## Further Resources

[Demos](./docs/Demos.md)  
[Installation instructions](./docs/Installation.md)  
[Cookbook](./docs/Cookbook.md)  
[Troubleshooting](./docs/Troubleshooting.md)  
[Build and Development instructions](./docs/Development.md)  
[Supported Hardware](./docs/Hardware.md)  
[Testing & Fuzzing](./docs/Testing.md)  
[Performance](./docs/Performance.md)  
[Interpreter Architecture](./docs/Interpreter.md)  
[Logging](./docs/Diagnostics.md)  
[Awesome WebAssembly Tools](https://github.com/vshymanskyy/awesome-wasm-tools/blob/main/README.md)

### License
This project is released under The MIT License (MIT)


[WasmProps]: https://github.com/WebAssembly/proposals/blob/main/README.md  "WebAssembly Finished Proposals"
