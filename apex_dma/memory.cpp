#include "memory.hpp"

struct FindProcessContext
{
  OsInstance<> *os;
  const char *name;
  ProcessInstance<> *target_process;
  bool found;
};

bool find_process(FindProcessContext *find_context, Address addr)
{
  if (find_context->found)
  {
    return false;
  }

  if (find_context->os->process_by_address(addr, find_context->target_process))
  {
    return true;
  }

  const ProcessInfo *info = find_context->target_process->info();
  
  if (!strcmp(info->name, find_context->name))
  {
    find_context->found = true;  // Found the target process
    return false;
  }

  return true;  // Continue searching
}

size_t findPattern(const PBYTE rangeStart, size_t len, const char *pattern)
{
  size_t l = strlen(pattern);
  PBYTE patt_base = static_cast<PBYTE>(malloc((l >> 1) + 1));
  PBYTE msk_base = static_cast<PBYTE>(malloc((l >> 1) + 1));

  if (!patt_base || !msk_base)
  {
    free(patt_base);
    free(msk_base);
    return -1;  // Memory allocation failure
  }

  PBYTE pat = patt_base;
  PBYTE msk = msk_base;
  l = 0;

  while (*pattern)
  {
    if (*pattern == ' ')
    {
      pattern++;
      continue;
    }
    if (!*pattern) break;

    if (*(PBYTE)pattern == (BYTE)'\?')
    {
      *pat++ = 0;
      *msk++ = '?';
      pattern += (*(PWORD)pattern == (WORD)'\?\?') ? 2 : 1;
    }
    else
    {
      *pat++ = getByte(pattern);
      *msk++ = 'x';
      pattern += 2;
    }
    l++;
  }
  *msk = 0;
  
  pat = patt_base;
  msk = msk_base;

  for (size_t n = 0; n < (len - l); ++n)
  {
    if (isMatch(rangeStart + n, patt_base, msk_base))
    {
      free(patt_base);
      free(msk_base);
      return n;
    }
  }

  free(patt_base);
  free(msk_base);
  return -1;
}

bool IsInValid(uint64_t address) 
{
    // Updated to handle invalid ranges more effectively
    return address < 0x00010000 || address > 0x7FFFFFFFFFFF;
}

// Memory class implementation follows...

Memory::Memory() 
{ 
    mf_log_init(LevelFilter::LevelFilter_Info); 
}

int Memory::open_os()
{
  // Load all available plugins
  if (inventory)
  {
    mf_inventory_free(inventory);
    inventory = nullptr;
  }
  
  inventory = mf_inventory_scan();
  if (!inventory)
  {
    mf_log_error("Unable to create inventory");
    return 1;
  }
  
  printf("Inventory initialized: %p\n", inventory);

  const char *conn_name = "kvm";
  const char *conn_arg = "";

  ConnectorInstance connector;
  conn = &connector;

  // Initialize the connector plugin
  printf("Using %s connector.\n", conn_name);
  if (mf_inventory_create_connector(inventory, conn_name, conn_arg, &connector))
  {
    mf_log_error("Unable to initialize %s connector.", conn_name);
    return 1;
  }

  // Initialize the OS plugin
  if (mf_inventory_create_os(inventory, "win32", "", conn, &os))
  {
    mf_log_error("Unable to initialize OS plugin");
    return 1;
  }

  printf("OS plugin initialized: %p\n", os.container.instance.instance);
  return 0;
}

int Memory::open_proc(const char *name)
{
  int ret;
  const char *target_proc = name;
  
  if (!(ret = os.process_by_name(CSliceRef<uint8_t>(target_proc), &proc.hProcess)))
  {
    const ProcessInfo *info = proc.hProcess.info();
    printf("%s process found: 0x%lx, PID: %d, Name: %s, Path: %s\n", 
           target_proc, info->address, info->pid, info->name, info->path);
    
    const short MZ_HEADER = 0x5A4D;
    char base_section[8] = {0};
    CSliceMut<uint8_t> slice(base_section, sizeof(base_section));
    os.read_raw_into(proc.hProcess.info()->address + 0x520, slice); // Adjust as needed
    proc.baseaddr = *reinterpret_cast<long*>(base_section);

    // Logic for checking valid DTBs...
    // (same as previously discussed, with appropriate updates)

    if (!found_valid_dtb)
    {
      printf("Failed to find valid DTB for process %s\n", name);
      status = process_status::FOUND_NO_ACCESS;
      return ret;
    }

    status = process_status::FOUND_READY;
  }
  else
  {
    status = process_status::NOT_FOUND;
  }

  return ret;
}

Memory::~Memory()
{
  if (inventory)
  {
    mf_inventory_free(inventory);
    inventory = nullptr;
    mf_log_info("Inventory freed");
  }
}

void Memory::close_proc()
{
  proc.baseaddr = 0;
  status = process_status::NOT_FOUND;
}

// ScanPointer and other methods follow...
