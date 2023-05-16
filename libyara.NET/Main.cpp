// each header that defines types that are part of the
// managed API must be added to this file.

// there's a type redef in yara.h so this needs
// to be included before anything that includes yara.h

// Disable warning from upstream file compiler.h
#pragma warning (disable:4324)

#include <stdexcept>

#include "YaraContext.h"
#include "YaraTypes.h"
#include "Exceptions.h"

#include "Compiler.h"
#include "Rules.h"
#include "Rule.h"
#include "Match.h"
#include "Scanner.h"
#include "ScanResult.h"

#include "QuickScan.h"
