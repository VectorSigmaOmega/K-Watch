#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../../bpf/kwatch_shared.h"

// We don't have a standalone "parser" function yet, it's inline in rb_cb.
// Let's define a mock handle_event for fuzzing the struct interpretation.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(kwatch_event)) {
        return 0;
    }

    struct kwatch_event e;
    memcpy(&e, data, sizeof(e));

    // Exercise some logic that uses the event fields
    if (e.protocol == 6) {
        // TCP logic
        (void)(e.tcp_flags & 0x02);
    }
    
    return 0;
}
