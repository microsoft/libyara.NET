# libyara.NET
A .NET wrapper for libyara that provides a simplified API for developing tools in C# and PowerShell.

This library is built against the [libyara NuGet pre-release](https://www.nuget.org/packages/libyara_vs2015_prerelease/) package which is based on yara's master branch. It contains the latest features and fixes (as well as any bugs) that may not be in the latest release builds of yara (currently 3.4).

## Reference
See the [libyara C API documentation](http://yara.readthedocs.io/en/v3.4.0/capi.html) for a general overview on how to use libyara. This API is adapted to present an API that is more consistent with .NET so usage differs slightly, but the core concepts remain the same.

**TODO: examples**

See the TestApp project for an example of using this library in C#.

## Limitations

* Modules are not currently supported
* Scan results are collected and returned (as compared with the callback approach normally used) which may result in high memory use.