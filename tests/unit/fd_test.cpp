#include "../../src/util/fd.h"
#include "../vendored/doctest.h"

TEST_CASE("UniqueFd rejects negative libbpf-style error fds") {
    util::UniqueFd invalid_errno_fd(-2);
    CHECK(!invalid_errno_fd.is_valid());

    invalid_errno_fd.reset(-17);
    CHECK(!invalid_errno_fd.is_valid());

    invalid_errno_fd.reset(0);
    CHECK(invalid_errno_fd.is_valid());
}
