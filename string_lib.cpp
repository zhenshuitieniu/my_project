#include "string_lib.h"

uint64_t string_lib::str_to_uint64(const char* s)
{
   uint64_t ret = 0;
   sscanf(s, "%u", &ret);
   return ret;
}

std::string string_lib::uint64_to_str(uint64_t a)
{
   char str[24];
   snprintf(str, 24, "%u", (long long)a);
   return str;
}

std::string string_lib::uint64_vec_to_str(const uint64_vector* vec)
{
   char delimiter = ',';
   std::string out_str;

   if (vec->empty()) {
      return out_str;
   }

   for (uint64_vector_const_iter iter  = vec->begin(); iter != vec->end(); iter++) {
      out_str += string_lib::uint64_to_str(*iter);
      out_str += delimiter;
   }

   out_str.resize(out_str.length()-1);
   return out_str;
}

bool string_lib::is_numeric(const std::string string)
{
   if(string.empty() )
      return false;

   if(string.find_first_not_of("0123456789") != std::string::npos)
      return false;

   return true;
}


/**
 * Read all directory entries into given string list.
 *
 * Warning: This list can be big when the dir has lots of entries, so use this carefully.
 *
 * @throw InvalidConfigException on error (e.g. path not exists)
 */
void string_lib::read_complete_dir(const char* path, string_list* out_names)
{
    errno = 0; // recommended by posix (readdir(3p) )

    DIR* dirp = opendir(path);
    if (!dirp) {
        PRINT_ERROR("Unable to open directory");
        return;
    }

    struct dirent *dir_entry = NULL;
    while ((dir_entry = readdir(dirp)) != NULL) {
        if ((strcmp(dir_entry->d_name, ".") != 0) && (strcmp(dir_entry->d_name, "..") != 0 )) {
            out_names->push_back(dir_entry->d_name);
        }
    }
    closedir(dirp);

    if (errno) {
        PRINT_ERROR("Unable to fetch directory entry from");
    }
}
