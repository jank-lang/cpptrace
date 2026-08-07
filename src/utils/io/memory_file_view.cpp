#include "utils/io/memory_file_view.hpp"

CPPTRACE_BEGIN_NAMESPACE
namespace detail {
    string_view memory_file_view::path() const {
        return object_path;
    }

    std::size_t memory_file_view::size() const {
        return data.size();
    }

    Result<monostate, internal_error> memory_file_view::read_bytes(bspan buffer, off_t offset) const {
        if(offset < 0) {
            return internal_error("Illegal read in memory file {}: offset {}", path(), offset);
        }
        if(offset + buffer.size() > data.size()) {
            return internal_error(
                "Illegal read in memory file {}: offset = {}, size = {}, file size = {}",
                path(), offset, buffer.size(), data.size()
            );
        }
        std::memcpy(buffer.data(), data.data() + offset, buffer.size());
        return monostate{};
    }
}
CPPTRACE_END_NAMESPACE
