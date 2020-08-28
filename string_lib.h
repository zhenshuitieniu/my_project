#ifndef __STRING_LIB_H_
#define __STRING_LIB_H_

#include <dirent.h>
#include "common.h"

class string_lib {
    public:
        static uint64_t str_to_uint64(const char* s);
        static std::string uint64_to_str(uint64_t a);
        static std::string uint64_vec_to_str(const uint64_vector* vec);
        static bool is_numeric(const std::string string);

        static void read_complete_dir(const char* path, string_list* out_names);

        static uint64_t str_to_uint64(const std::string s) {
            return str_to_uint64(s.c_str() );
        }
};

#endif
