#include "common.h"
#include "string_lib.h"
/**
 * Returns the number of numa nodes by reading /sys/devices/system/node/nodeXY
 */
int get_num_numa_nodes()
{
    const char* path = "/sys/devices/system/node";
    const char* search_entry = "node";
    size_t search_entry_str_len = strlen(search_entry);
    int num_numa_nodes = 0;

    if (path_exists(path)) {
        PRINT_ERROR("NUMA node check path not found:  %s . Assuming single NUMA node, path: %s\n", path);
        return 1;
    }

    string_list path_entries;
    string_lib::read_complete_dir(path, &path_entries);
    for (string_list_const_iter iter = path_entries.begin(); iter != path_entries.end(); iter++) {
        if (!strncmp(search_entry, iter->c_str(), search_entry_str_len) )
            num_numa_nodes++; // found a numa node
    }

    return MAX(num_numa_nodes, 1);
}

/**
 * Returns the CPU cores that belong to the given numa node
 */
int get_numa_cores_by_node(int node_num, cpu_set_t *out_cpu_set, uint64_vector *out_cpu_ids)
{
    std::string path = "/sys/devices/system/node/node" + string_lib::uint64_to_str(node_num);
    const char* search_entry = "cpu";
    size_t search_entry_str_len = strlen(search_entry);

    int num_cores = 0; // detected number of cores for the given numa node

    CPU_ZERO(out_cpu_set); // initialize the set

    if (path_exists((const char *)path.c_str())) {
        PRINT_ERROR("NUMA core check path not found, path: %s\n", path.c_str());
        return 1;
    }

    string_list path_entries;
    string_lib::read_complete_dir(path.c_str(), &path_entries);

    for (string_list_const_iter iter = path_entries.begin(); iter != path_entries.end(); iter++) {
        if (!strncmp(search_entry, iter->c_str(), search_entry_str_len)) { // found a core for this numa node
            num_cores++;

            std::string core_num_str = std::string(iter->c_str() ).substr(search_entry_str_len);

            // note: there are other entries that start with "cpu" as well, so we check for digits:
            if(core_num_str.empty() || !isdigit(core_num_str[0] ) )
                continue;

            CPU_SET(string_lib::str_to_uint64(core_num_str), out_cpu_set);
            out_cpu_ids->push_back(string_lib::str_to_uint64(core_num_str));
        }
    }

    if (!num_cores) {
        PRINT_ERROR("No cores found");
    }

    return num_cores;
}

/**
 * Set affinity of current process to given NUMA zone.
 */
bool bind_to_numa_node(int node_num)
{
    cpu_set_t cpu_set;
    uint64_vector out_cpu_ids;

    int numCores = get_numa_cores_by_node(node_num, &cpu_set, &out_cpu_ids);
    if (!numCores) { // something went wrong with core retrieval, so fall back to running on all cores
        PRINT_ERROR("Failed to detect CPU cores for NUMA zone. Falling back to allowing all cores node: %d\n", node_num);
        return false;
    }

    if (sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set)) { // failed to set affinity
        PRINT_ERROR("Failed to set process affinity to NUMA zone. Failed zone\n");
        return false;
    }

    return true;
}
