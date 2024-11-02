#include "memory.hpp"
#include <unordered_map>
#include <cstring>
#include <fstream>
#include <sstream>
#include <set>
#include <iostream>

struct FindProcessContext {
    OsInstance<> *os;
    const char *name;
    ProcessInstance<> *target_process;
    bool found;
};

bool find_process(FindProcessContext *find_context, Address addr) {
    if (find_context->found) {
        return false; // Already found
    }

    // Check if the address matches a process
    if (find_context->os->process_by_address(addr, find_context->target_process)) {
        return true; // Found a process at this address
    }

    const ProcessInfo *info = find_context->target_process->info();
    if (info && strcmp(info->name, find_context->name) == 0) {
        find_context->found = true; // Process found
        return false; // Abort iteration
    }

    return true; // Continue iteration
}

size_t findPattern(const PBYTE rangeStart, size_t len, const char *pattern) {
    size_t l = strlen(pattern);
    size_t max_pattern_length = (l >> 1) + 1; // Allocate enough space
    PBYTE patt_base = static_cast<PBYTE>(malloc(max_pattern_length));
    PBYTE msk_base = static_cast<PBYTE>(malloc(max_pattern_length));

    if (!patt_base || !msk_base) {
        free(patt_base);
        free(msk_base);
        return -1; // Memory allocation failed
    }

    PBYTE pat = patt_base;
    PBYTE msk = msk_base;
    size_t pattern_length = 0;

    while (*pattern) {
        if (*pattern == ' ') {
            pattern++;
            continue;
        }
        if (*pattern == '\0') break;

        if (*pattern == '?') {
            *pat++ = 0; // Wildcard
            *msk++ = '?';
            pattern += (*reinterpret_cast<PWORD>(pattern) == '\?\?') ? 2 : 1;
        } else {
            *pat++ = getByte(pattern);
            *msk++ = 'x';
            pattern += 2;
        }
        pattern_length++;
    }
    *msk = 0; // Null terminate the mask

    for (size_t n = 0; n <= len - pattern_length; ++n) {
        if (isMatch(rangeStart + n, patt_base, msk_base)) {
            free(patt_base);
            free(msk_base);
            return n; // Found pattern
        }
    }

    free(patt_base);
    free(msk_base);
    return -1; // Pattern not found
}

uint64_t Memory::get_proc_baseaddr() { 
    return proc.baseaddr; 
}

process_status Memory::get_proc_status() { 
    return status; 
}

void Memory::check_proc() {
    if (status == process_status::FOUND_READY) {
        short c;
        if (Read<short>(proc.baseaddr, c) && c != 0x5A4D) {
            status = process_status::FOUND_NO_ACCESS;
            close_proc();
        }
    }
}

Memory::Memory() { 
    mf_log_init(LevelFilter::LevelFilter_Info); 
}

int Memory::open_os() {
    // Load all available plugins
    if (inventory) {
        mf_inventory_free(inventory);
        inventory = nullptr;
    }

    inventory = mf_inventory_scan();
    if (!inventory) {
        mf_log_error("Unable to create inventory");
        return 1;
    }
    printf("Inventory initialized: %p\n", inventory);

    ConnectorInstance connector;
    conn = &connector;

    // Initialize the connector plugin
    const char *conn_names[] = { "kvm", "qemu" };
    for (const char *conn_name : conn_names) {
        printf("Using %s connector.\n", conn_name);
        if (mf_inventory_create_connector(inventory, conn_name, "", &connector) == 0) {
            printf("Connector initialized: %p\n", connector.container.instance.instance);
            break;
        } else {
            printf("Unable to initialize %s connector.\n", conn_name);
        }
    }

    // Initialize the OS plugin
    if (mf_inventory_create_os(inventory, "win32", "", conn, &os)) {
        printf("Unable to initialize OS\n");
        return 1;
    }

    printf("OS plugin initialized: %p\n", os.container.instance.instance);
    return 0;
}

const std::string filename = "DTB.txt";

bool check_exist() {
    std::ifstream file(filename);
    if (!file) {
        printf("DTB file does not exist.\n");
        return false;
    }
    return true;
}

std::set<size_t> load_valid_dtbs() {
    std::set<size_t> dtb_set;
    std::ifstream file(filename);
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        size_t dtb;
        if (iss >> dtb) {
            dtb_set.insert(dtb);
        }
    }
    return dtb_set;
}

void append_valid_dtb(size_t dtb) {
    std::ofstream file(filename, std::ios::app);
    file << dtb << std::endl;
}

int Memory::open_proc(const char *name) {
    int ret;
    bool exist_dtb_file = check_exist();
    std::set<size_t> valid_dtbs = load_valid_dtbs();

    if ((ret = os.process_by_name(CSliceRef<uint8_t>(name), &proc.hProcess)) == 0) {
        const ProcessInfo *info = proc.hProcess.info();
        printf("%s process found: 0x%lx %d %s %s\n", name, info->address, info->pid, info->name, info->path);

        const short MZ_HEADER = 0x5A4D;
        char base_section[8] = {0};
        CSliceMut<uint8_t> slice(base_section, sizeof(base_section));
        os.read_raw_into(info->address + 0x520, slice); // For win10
        proc.baseaddr = *reinterpret_cast<long*>(base_section);

        bool found_valid_dtb = false;

        if (exist_dtb_file) {
            for (size_t dtb : valid_dtbs) {
                proc.hProcess.set_dtb(dtb, Address_INVALID);
                short header;
                Read<short>(*reinterpret_cast<long*>(base_section), header);
                if (header == MZ_HEADER) {
                    printf("Using valid DTB from file: %zu\n", dtb);
                    found_valid_dtb = true;
                    break;
                }
            }
        }

        if (!found_valid_dtb) {
            printf("Searching for a new DTB...\n");
            for (size_t dtb = 0; dtb < SIZE_MAX; dtb += 4096) {
                proc.hProcess.set_dtb(dtb, Address_INVALID);
                short header;
                Read<short>(*reinterpret_cast<long*>(base_section), header);
                if (header == MZ_HEADER) {
                    printf("Found new DTB: %zu\n", dtb);
                    append_valid_dtb(dtb);
                    found_valid_dtb = true;
                    break;
                }
            }
        }

        if (!found_valid_dtb) {
            printf("Failed to find valid DTB for process %s\n", name);
            status = process_status::FOUND_NO_ACCESS;
            return ret;
        }
        status = process_status::FOUND_READY;
    } else {
        status = process_status::NOT_FOUND;
    }

    return ret;
}

Memory::~Memory() {
    if (inventory) {
        mf_inventory_free(inventory);
        inventory = nullptr;
        mf_log_info("Inventory freed");
    }
}

void Memory::close_proc() {
    proc.baseaddr = 0;
    status = process_status::NOT_FOUND;
}

uint64_t Memory::ScanPointer(uint64_t ptr_address, const uint32_t offsets[], int level) {
    if (!ptr_address) return 0;

    uint64_t lvl = ptr_address;

    for (int i = 0; i < level; i++) {
        if (!Read<uint64_t>(lvl, lvl) || !lvl) {
            return 0; // Invalid pointer read
        }
        lvl += offsets[i];
    }

    return lvl;
}

bool IsInValid(uint64_t address) {
    return address < 0x00010000 || address > 0x7FFFFFFEFFFF; // Validate address range
}
