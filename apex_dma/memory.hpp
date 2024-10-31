#include "memflow.hpp"
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdio.h>
#include <fstream>
#include <sstream>
#include <string>
#include <set>

#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x) \
  (INRANGE(x, '0', '9') ? (x - '0') : ((x & (~0x20)) - 'A' + 0xa))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))

typedef uint8_t *PBYTE;
typedef uint8_t BYTE;
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef WORD *PWORD;

static ConnectorInstance<> *conn = 0;

// Cache structure
struct CacheEntry {
    uintptr_t address; // Address of the page table entry
    MMPTE value;       // Page table entry value
    bool valid;       // Indicates if the cache entry is valid
};

class Memory
{
private:
    Inventory *inventory;
    OsInstance<> os;
    Process proc;
    process_status status = process_status::NOT_FOUND;
    std::mutex m;

    // Caches for page tables
    static const int CACHE_SIZE = 512; // Size of the cache
    CacheEntry cached_pml4e[CACHE_SIZE]; // PML4E cache
    CacheEntry cached_pdpte[CACHE_SIZE];  // PDPT cache
    CacheEntry cached_pde[CACHE_SIZE];     // PDE cache
    CacheEntry cached_pte[CACHE_SIZE];     // PTE cache

public:
    Memory();
    ~Memory();

    uint64_t get_proc_baseaddr();
    process_status get_proc_status();
    void check_proc();
    int open_os();
    int open_proc(const char *name);
    void close_proc();

    template <typename T>
    bool Read(uint64_t address, T &out);

    template <typename T>
    bool ReadArray(uint64_t address, T out[], size_t len);

    template <typename T>
    bool Write(uint64_t address, const T &value);

    template <typename T>
    bool WriteArray(uint64_t address, const T value[], size_t len);

    uint64_t ScanPointer(uint64_t ptr_address, const uint32_t offsets[], int level);

   
    bool getCachedPML4E(uint64_t address, MMPTE &outValue);
    void setCachedPML4E(uint64_t address, const MMPTE &value);


};


inline bool Memory::getCachedPML4E(uint64_t address, MMPTE &outValue) {
    size_t index = (address >> 39) & 0x1FF; // Calculate index for PML4E
    if (cached_pml4e[index].address == address && cached_pml4e[index].valid) {
        outValue = cached_pml4e[index].value; // Return cached value
        return true;
    }
    return false; // Not found in cache
}

inline void Memory::setCachedPML4E(uint64_t address, const MMPTE &value) {
    size_t index = (address >> 39) & 0x1FF; // Calculate index for PML4E test
    cached_pml4e[index].address = address;
    cached_pml4e[index].value = value;
    cached_pml4e[index].valid = true; // Mark as valid
}

bool check_exist();
std::set<size_t> load_valid_dtbs();
void append_valid_dtb(size_t dtb);
bool IsInValid(uint64_t address);
