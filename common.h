#ifndef __COMMON_H_
#define __COMMON_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <inttypes.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <list>
#include <vector>

#include "debug.h"

#define MIN(a, b)           ( ( (a) < (b) ) ? (a) : (b) )
#define MAX(a, b)           ( ( (a) < (b) ) ? (b) : (a) )

// gcc branch optimization hints
#define likely(x)           __builtin_expect(!!(x), 1)
#define unlikely(x)         __builtin_expect(!!(x), 0)

typedef std::list<std::string>              string_list;
typedef string_list::iterator               string_list_iter;
typedef string_list::const_iterator         string_list_const_iter;

typedef std::vector<std::string>            string_vector;
typedef string_vector::iterator             string_vector_iter;
typedef string_vector::const_iterator       string_vector_const_iter;

typedef std::set<std::string>               string_set;
typedef string_set::iterator                string_set_iter;
typedef string_set::const_iterator          string_set_const_iter;

typedef std::map<std::string, uint64_t>     string_uint64_map;
typedef string_uint64_map::iterator         string_uint64_map_iter;
typedef string_uint64_map::const_iterator   string_uint64_map_const_iter;

typedef std::map<std::string, std::string>  string_map;
typedef string_map::iterator                string_map_iter;
typedef string_map::const_iterator          string_map_const_iter;

typedef std::list<uint64_t>                 uint64_list;
typedef uint64_list::iterator               uint64_list_iter;
typedef uint64_list::const_iterator         uint64_list_const_iter;

typedef std::vector<uint64_t>               uint64_vector;
typedef uint64_vector::iterator             uint64_vector_iter;
typedef uint64_vector::const_iterator       uint64_vector_const_iter;

typedef std::set<uint64_t>                  uint64_set;
typedef uint64_set::iterator                uint64_set_iter;
typedef uint64_set::const_iterator          uint64_set_const_iter;

static bool path_exists(const char *path)
{
   return access(path, F_OK);
}

int get_num_numa_nodes();
int get_numa_cores_by_node(int node_num, cpu_set_t *out_cpu_set, uint64_vector *out_cpu_ids);
bool bind_to_numa_node(int node_num);

#endif /*__COMMON_H_*/
