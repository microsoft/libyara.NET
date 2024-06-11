# libyara.NET
A .NET wrapper for libyara that provides a simplified API for developing tools in C# and PowerShell. This library targets .NET 4.6.2.

This library is built against the [Microsoft.O365.Security.Native.Libyara](https://www.nuget.org/packages/Microsoft.O365.Security.Native.Libyara/) package which is based on VirusTotal's [yara](https://github.com/VirusTotal/yara/) built with [vcpkg](https://github.com/Microsoft/vcpkg/). This library is currently based on yara 4.5.1 per the [vcpkg port](https://github.com/microsoft/vcpkg/tree/master/ports/yara). We will update [yara](https://github.com/VirusTotal/yara/) version to include the latest features and bug fixes if necessary.

This library is available in forms of two NuGet packages, depending on your project types:

For .NET framework projects, x86, x64 and ARM64 binary versions are available on NuGet with the package id [Microsoft.O365.Security.Native.libyara.NET](https://www.nuget.org/packages/Microsoft.O365.Security.Native.libyara.NET/). The public key token of official binaries is `31bf3856ad364e35`. Projects that use libyara.NET should use 'Any CPU' or 'x86' as the platform name to select the x86 binaries, use 'x64' to select the x64 binaries and use 'ARM64' to select the ARM64 binaries.

For .NET Core projects, only x64 and ARM64 binary versions are available on NuGet with the package id [Microsoft.O365.Security.Native.libyara.NET.Core](https://www.nuget.org/packages/Microsoft.O365.Security.Native.libyara.NET.Core/). The public key token of official binaries is `31bf3856ad364e35`. Projects that use libyara.NET should use 'x64' or 'ARM64' as the platform name to use this NuGet package.

## Quick Start

	static void Main(string[] args)
	{
	    // Use the QuickScan class when you don't need to reuse rules
	    // or other yara objects. QuickScan handles all of the resource
	    // management including the YaraContext.

	    // var results = QuickScan.File(".\\SampleFile.txt", ".\\HelloWorldRules.yara");

	    // When you need to reuse yara objects (e.g. when scanning multiple files) it's
	    // more efficient to use the pattern below. Note that all yara operations must
	    // take place within the scope of a YaraContext.
	    using (var ctx = new YaraContext())
	    {
	        Rules rules = null;

	        try
	        {
	            // Rules and Compiler objects must be disposed.
	            using (var compiler = new Compiler())
	            {
	                compiler.AddRuleFile(".\\HelloWorldRules.yara");
	                rules = compiler.GetRules();
	            }

	            // Scanner and ScanResults do not need to be disposed.
	            var scanner = new Scanner();
	            var results = scanner.ScanFile(".\\SampleFile.txt", rules);
	        }
	        finally
	        {
	            // Rules and Compiler objects must be disposed.
	            if (rules != null) rules.Dispose();
	        }
	    }
	}


## Reference
See the [libyara C API documentation](https://yara.readthedocs.io/en/v4.0.2/capi.html) for a general overview on how to use libyara. This API is adapted to present an API that is more consistent with .NET so usage differs slightly, but the core concepts remain the same.

**TODO: API Reference**

## Limitations

* Rule metadata not supported
* Modules are not currently supported
* Scan results are collected and returned (as compared with the callback approach normally used) which may result in high memory use with rules that match many items.
