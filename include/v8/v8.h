#ifndef V8_V8_H_
#define V8_V8_H_

/**
 * TechnoScript V8-Compatible API
 * 
 * This is a V8-compatible API implementation that allows applications
 * to use TechnoScript as a drop-in replacement for the V8 JavaScript engine.
 */

#include "v8/v8-version.h"
#include "v8/v8-internal.h"
#include "v8/v8-isolate.h"
#include "v8/v8-local-handle.h"
#include "v8/v8-persistent-handle.h"
#include "v8/v8-handle-scope.h"
#include "v8/v8-context.h"
#include "v8/v8-primitive.h"
#include "v8/v8-value.h"
#include "v8/v8-object.h"
#include "v8/v8-function.h"
#include "v8/v8-template.h"
#include "v8/v8-script.h"
#include "v8/v8-exception.h"

/**
 * The v8 namespace contains all V8 API types and functions.
 */
namespace v8 {

/**
 * Container class for static utility functions.
 */
class V8 {
public:
    /**
     * Initialize the V8 engine.
     * This must be called before creating any isolates.
     */
    static bool Initialize();
    
    /**
     * Dispose of all resources allocated by V8.
     */
    static bool Dispose();
    
    /**
     * Get the version string.
     */
    static const char* GetVersion();
    
    /**
     * Set V8 flags from the command line.
     */
    static void SetFlagsFromCommandLine(int* argc, char** argv, bool remove_flags);
    
    /**
     * Set V8 flags from a string.
     */
    static void SetFlagsFromString(const char* str, size_t length);
};

}  // namespace v8

#endif  // V8_V8_H_
