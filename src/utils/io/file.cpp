#define _CRT_SECURE_NO_WARNINGS
#include "utils/io/file.hpp"

CPPTRACE_BEGIN_NAMESPACE
namespace detail {
    string_view file::path() const {
        return object_path;
    }

    std::size_t file::size() const {
        return file_size;
    }

    Result<file, internal_error> file::open(cstring_view object_path) {
        auto file_obj = raii_wrap(std::fopen(object_path.c_str(), "rb"), file_deleter);
        if(file_obj == nullptr) {
            return internal_error("Unable to read object file {}", object_path);
        }
        if(std::fseek(file_obj, 0, SEEK_END) != 0) {
            return internal_error("fseek error in {} while determining file size", object_path);
        }
        auto const end = std::ftell(file_obj);
        if(end < 0) {
            return internal_error("ftell error in {} while determining file size", object_path);
        }
        return file(std::move(file_obj), object_path, static_cast<std::size_t>(end));
    }

    Result<monostate, internal_error> file::read_bytes(bspan buffer, off_t offset) const {
        if(std::fseek(file_obj, offset, SEEK_SET) != 0) {
            return internal_error("fseek error in {} at offset {}", path(), offset);
        }
        if(std::fread(buffer.data(), buffer.size(), 1, file_obj) != 1) {
            return internal_error("fread error in {} at offset {} for {} bytes", path(), offset, buffer.size());
        }
        return monostate{};
    }
}
CPPTRACE_END_NAMESPACE
