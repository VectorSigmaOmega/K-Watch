#pragma once

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include <bpf/bpf.h>

#include "../util/result.h"
#include "flow_tracker.h"

namespace core {

class FlowStateSnapshot {
    std::vector<FlowMapEntry> entries_;

  public:
    explicit FlowStateSnapshot(size_t capacity = 65536) { entries_.reserve(capacity); }

    util::Result<void> refresh(int flow_state_fd) {
        entries_.clear();

        kwatch_flow_key current_key{};
        kwatch_flow_key next_key{};
        void *lookup_key = nullptr;

        errno = 0;
        while (bpf_map_get_next_key(flow_state_fd, lookup_key, &next_key) == 0) {
            FlowMapEntry entry{};
            entry.key = next_key;
            if (bpf_map_lookup_elem(flow_state_fd, &next_key, &entry.stats) == 0) {
                entries_.push_back(entry);
            }
            current_key = next_key;
            lookup_key = &current_key;
        }

        if (errno != 0 && errno != ENOENT) {
            return util::Result<void>::Err("flow_state snapshot failed: " +
                                           std::string(std::strerror(errno)));
        }
        return util::Result<void>::Ok();
    }

    const std::vector<FlowMapEntry> &entries() const { return entries_; }
};

} // namespace core
