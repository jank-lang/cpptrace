#ifndef CPPTRACE_FORMATTING_HPP
#define CPPTRACE_FORMATTING_HPP

#include <cpptrace/basic.hpp>

#include <string>
#include <functional>

namespace cpptrace {
    class CPPTRACE_EXPORT formatter {
        class impl;
        // can't be a std::unique_ptr due to msvc awfulness with dllimport/dllexport and https://stackoverflow.com/q/4145605/15675011
        impl* pimpl;

    public:
        formatter();
        ~formatter();

        formatter(formatter&&);
        formatter(const formatter&);
        formatter& operator=(formatter&&);
        formatter& operator=(const formatter&);

        formatter& header(std::string);
        enum class color_mode {
            always,
            none,
            automatic,
        };
        formatter& colors(color_mode);
        enum class address_mode {
            raw,
            object,
            none,
        };
        formatter& addresses(address_mode);
        enum class path_mode {
            // full path is used
            full,
            // only the file name is used
            basename,
        };
        formatter& paths(path_mode);
        formatter& snippets(bool);
        formatter& snippet_context(int);
        formatter& columns(bool);
        formatter& filtered_frame_placeholders(bool);
        formatter& filter(std::function<bool(const stacktrace_frame&)>);
        formatter& transform_frame(std::function<void(stacktrace_frame&)>);

        std::string format(stacktrace_frame&) const;
        std::string format(stacktrace_frame&, bool color) const;

        std::string format(stacktrace&) const;
        std::string format(stacktrace&, bool color) const;

        void print(stacktrace_frame&) const;
        void print(stacktrace_frame&, bool color) const;
        void print(std::ostream&, stacktrace_frame&) const;
        void print(std::ostream&, stacktrace_frame&, bool color) const;
        void print(std::FILE*, stacktrace_frame&) const;
        void print(std::FILE*, stacktrace_frame&, bool color) const;

        void print(stacktrace&) const;
        void print(stacktrace&, bool color) const;
        void print(std::ostream&, stacktrace&) const;
        void print(std::ostream&, stacktrace&, bool color) const;
        void print(std::FILE*, stacktrace&) const;
        void print(std::FILE*, stacktrace&, bool color) const;
    };

    CPPTRACE_EXPORT const formatter& get_default_formatter();
}

#endif
