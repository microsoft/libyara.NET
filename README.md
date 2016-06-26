# libyara.NET
A .NET wrapper for libyara that provides a simplified API for developing tools in C# and PowerShell. This library targets .NET 4.5.

This library is built against the [libyara NuGet pre-release](https://www.nuget.org/packages/libyara_vs2015_prerelease/) package which is based on yara's master branch. It contains the latest features and fixes (as well as any bugs) that may not be in the latest release builds of yara (currently 3.4).

An x64 binary version is available on NuGet with the package id [libyara.NET](https://www.nuget.org/packages/libyara.NET)

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
See the [libyara C API documentation](http://yara.readthedocs.io/en/v3.4.0/capi.html) for a general overview on how to use libyara. This API is adapted to present an API that is more consistent with .NET so usage differs slightly, but the core concepts remain the same. Also, because this is built against a pre-release version of yara, the API may have changed slightly from the documentation.

**TODO: API Reference**

## Limitations

* Rule metadata not supported
* Modules are not currently supported
* Scan results are collected and returned (as compared with the callback approach normally used) which may result in high memory use with rules that match many items.
