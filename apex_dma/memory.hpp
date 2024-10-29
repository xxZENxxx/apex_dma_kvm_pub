#include "memflow.hpp"
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdio.h>
#include <fstream>
#include <sstream>
#include <string>
#include <set>
#include <chrono>

#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x) \
  (INRANGE(x, '0', '9') ? (x - '0') : ((x & (~0x20)) - 'A' + 0xa))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))

typedef uint8_t *PBYTE;
typedef uint8_t BYTE;
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef WORD *PWORD;

static ConnectorInstance<> *conn = nullptr;

inline bool isMatch(const PBYTE addr, const PBYTE pat, const PBYTE msk)
{
  size_t n = 0;
  while (addr[n] == pat[n] || msk[n] == (BYTE)'?')
  {
    if (!msk[++n])
    {
      return true;
    }
  }
  return false;
}

size_t findPattern(const PBYTE rangeStart, size_t len, const char *pattern);

typedef struct Process
{
  ProcessInstance<> hProcess;
  uint64_t baseaddr = 0;
} Process;

enum class process_status : BYTE
{
  NOT_FOUND,
  FOUND_NO_ACCESS,
  FOUND_READY
};

class Memory
{
private:
  Inventory *inventory = nullptr;
  OsInstance<> os;
  Process proc;
  process_status status = process_status::NOT_FOUND;
  std::mutex m;
  std::chrono::steady_clock::time_point last_check_time;

public:
  Memory();
  ~Memory();

  uint64_t get_proc_baseaddr();
  process_status get_proc_status();

  void check_proc();
  void adaptive_pdb_check(); // Added to adapt to shuffling PDB

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
};

template <typename T>
inline bool Memory::Read(uint64_t address, T &out)
{
  std::lock_guard<std::mutex> l(m);
  if (proc.baseaddr && !IsInValid(address))
  {
    return proc.hProcess.read_raw_into(
               address, CSliceMut<uint8_t>((char *)&out, sizeof(T))) == 0;
  }
  return false;
}

template <typename T>
inline bool Memory::ReadArray(uint64_t address, T out[], size_t len)
{
  std::lock_guard<std::mutex> l(m);
  if (proc.baseaddr && !IsInValid(address))
  {
    return proc.hProcess.read_raw_into(
               address, CSliceMut<uint8_t>((char *)out, sizeof(T) * len)) == 0;
  }
  return false;
}

template <typename T>
inline bool Memory::Write(uint64_t address, const T &value)
{
  std::lock_guard<std::mutex> l(m);
  if (proc.baseaddr && !IsInValid(address))
  {
    return proc.hProcess.write_raw(
               address, CSliceRef<uint8_t>((const char *)&value, sizeof(T))) == 0;
  }
  return false;
}

template <typename T>
inline bool Memory::WriteArray(uint64_t address, const T value[], size_t len)
{
  std::lock_guard<std::mutex> l(m);
  if (proc.baseaddr && !IsInValid(address))
  {
    return proc.hProcess.write_raw(
               address, CSliceRef<uint8_t>((const char *)value, sizeof(T) * len)) == 0;
  }
  return false;
}

bool check_exist();
std::set<size_t> load_valid_dtbs();
void append_valid_dtb(size_t dtb);
bool IsInValid(uint64_t address);
