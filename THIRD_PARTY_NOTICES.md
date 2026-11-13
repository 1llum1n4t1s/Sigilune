# Third-party notices

## ssign / ssign-core

Sigilune uses the [`ssign-core`](https://crates.io/crates/ssign-core) crate for the
Certum SimplySign cloud protocol (OAuth login, card and certificate retrieval,
remote digest signature). The following files are also copied from the
[ssign](https://github.com/Le-Syl21/ssign) repository:

- `crates/sigilune-core/certs/ccsca2021.der`, `crates/sigilune-core/certs/cevcsca2021.der`
  (public Certum intermediate CA certificates)
- `crates/sigilune-core/tests/fixtures/hello.exe`, `test.msi`, `selftest_cert.der`,
  `selftest_key.pem` (test fixtures; the key is a throwaway self-signed test key)

```
MIT License

Copyright (c) 2026 Sylvain

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```


## MSBuild (mansign2.cs)

`dotnet/Sigilune.Manifest/ManifestSigning.cs` is ported from
[`src/Tasks/ManifestUtil/mansign2.cs`](https://github.com/dotnet/msbuild/blob/main/src/Tasks/ManifestUtil/mansign2.cs)
in the [dotnet/msbuild](https://github.com/dotnet/msbuild) repository
(ClickOnce manifest signing). The changes are described at the top of that file.

```
The MIT License (MIT)

Copyright (c) .NET Foundation and contributors

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Other Rust dependencies are listed in `Cargo.lock`; each is distributed under its
own license (mostly MIT / Apache-2.0).
