#include "mem.h"
#include "stdlib.h"
#include "string.h"
#include <pthread.h>
#include <stdio.h>

static BYTE _ram[RAM_SIZE];

static struct
{
  uint32_t proc; // ID of process currently uses this page
  int index;     // Index of the page in the list of pages allocated
                 // to the process.
  int next;      // The next page in the list. -1 if it is the last page.
} _mem_stat[NUM_PAGES];

static pthread_mutex_t mem_lock;

void
init_mem (void)
{
  memset (_mem_stat, 0, sizeof (*_mem_stat) * NUM_PAGES);
  memset (_ram, 0, sizeof (BYTE) * RAM_SIZE);
  pthread_mutex_init (&mem_lock, NULL);
}

/* get offset of the virtual address */
static addr_t
get_offset (addr_t addr)
{
  return addr & ~((~0U) << OFFSET_LEN);
}

/* get the first layer index */
static addr_t
get_first_lv (addr_t addr)
{
  return addr >> (OFFSET_LEN + PAGE_LEN);
}

/* get the second layer index */
static addr_t
get_second_lv (addr_t addr)
{
  return (addr >> OFFSET_LEN) - (get_first_lv (addr) << PAGE_LEN);
}

/* Search for page table table from the a segment table */
static struct page_table_t *
get_page_table (addr_t index, // Segment level index
                struct seg_table_t *seg_table)
{
  /*
   * TODO: Given the Segment index [index], you must go through each
   * row of the segment table [seg_table] and check if the v_index
   * field of the row is equal to the index
   *
   */

  return seg_table->table[index].pages;
}

/* Translate virtual address to physical address. If [virtual_addr] is valid,
 * return 1 and write its physical counterpart to [physical_addr].
 * Otherwise, return 0 */
static int
translate (addr_t virtual_addr,   // Given virtual address
           addr_t *physical_addr, // Physical address to be returned
           struct pcb_t *proc)    // Process uses given virtual address
{
  /* Offset of the virtual address */
  addr_t offset = get_offset (virtual_addr);
  /* The first layer index */
  addr_t first_lv = get_first_lv (virtual_addr);
  /* The second layer index */
  addr_t second_lv = get_second_lv (virtual_addr);

  /* Search in the first level */
  struct page_table_t *page_table = NULL;
  page_table = get_page_table (first_lv, proc->seg_table);
  if (page_table == NULL)
    return 0;

  // Check if Virtual address has really been allocated
  if (page_table->table[second_lv].v_index == -1)
    return 0;

  /* TODO: Concatenate the offset of the virtual address
   * to [p_index] field of page_table->table[i] to
   * produce the correct physical address and save it to
   * [*physical_addr]  */

  *physical_addr
      = (page_table->table[second_lv].p_index << OFFSET_LEN) + offset;
  return 1;
}

void
alloc_page_table (struct pcb_t *proc, addr_t first_lv)
{
  proc->seg_table->table[first_lv].pages
      = malloc (sizeof (struct page_table_t));
  proc->seg_table->table[first_lv].pages->size = 0;

  struct page_table_t *page_table = get_page_table (first_lv, proc->seg_table);
  for (int j = 0; j < (1 << PAGE_LEN); j++)
    page_table->table[j].v_index = -1;

  proc->seg_table->table[first_lv].v_index = first_lv;
  proc->seg_table->size++;
}

addr_t
alloc_mem (uint32_t size, struct pcb_t *proc)
{
  addr_t ret_mem = 0;
  /* TODO: Allocate [size] byte in the memory for the
   * process [proc] and save the address of the first
   * byte in the allocated memory region to [ret_mem].
   */

  // Number of pages we will use
  uint32_t num_pages = size / PAGE_SIZE;
  if (size % PAGE_SIZE)
    num_pages += 1;

  /* First we must check if the amount of free memory in
   * virtual address space and physical address space is
   * large enough to represent the amount of required
   * memory. If so, set 1 to [mem_avail].
   * Hint: check [proc] bit in each page of _mem_stat
   * to know whether this page has been used by a process.
   * For virtual memory space, check bp (break pointer).
   * */

  // Has allocated memory amount exceeds maximum allowed
  if (proc->bp + num_pages * PAGE_SIZE > (1 << ADDRESS_SIZE))
    return 0;

  pthread_mutex_lock (&mem_lock);

  // Check if we have enough memory to allocate
  int empty_page = 0;
  for (int i = 0; i < NUM_PAGES; i++)
    {
      if (_mem_stat[i].proc == 0)
        ++empty_page;
      if (empty_page == num_pages)
        break;
    }

  if (empty_page < num_pages)
    {
      pthread_mutex_unlock (&mem_lock);
      return 0;
    }

  /* We could allocate new memory region to the process */
  ret_mem = proc->bp;
  proc->bp += num_pages * PAGE_SIZE;
  /* Update status of physical pages which will be allocated
   * to [proc] in _mem_stat. Tasks to do:
   * 	- Update [proc], [index], and [next] field
   * 	- Add entries to segment table page tables of [proc]
   * 	  to ensure accesses to allocated memory slot is
   * 	  valid. */
  int counter = 0;
  int prev = -1;
  addr_t vir_mem = ret_mem;
  for (int i = 0; i < NUM_PAGES; ++i)
    {
      // Skip is page is occupied
      if (_mem_stat[i].proc != 0)
        continue;

      // update status of physical pages
      _mem_stat[i].proc = proc->pid;
      _mem_stat[i].index = counter;

      if (prev != -1)
        _mem_stat[prev].next = i;
      prev = i;

      addr_t first_lv = get_first_lv (vir_mem);
      addr_t second_lev = get_second_lv (vir_mem);

      // if page_table is NULL, alloc page_table
      if (!proc->seg_table->table[first_lv].pages)
        alloc_page_table (proc, first_lv);

      // update page_table
      struct page_table_t *page_table
          = get_page_table (first_lv, proc->seg_table);

      page_table->table[second_lev].v_index = second_lev;
      page_table->table[second_lev].p_index = i;
      page_table->size++;

      vir_mem += PAGE_SIZE;

      // All pages have been allocated, stop
      if (++counter == num_pages)
        {
          _mem_stat[i].next = -1;
          break;
        }
    }

  pthread_mutex_unlock (&mem_lock);
  return ret_mem;
}

int
free_mem (addr_t address, struct pcb_t *proc)
{
  /*TODO: Release memory region allocated by [proc]. The first byte of
   * this region is indicated by [address]. Task to do:
   * 	- Set flag [proc] of physical page use by the memory block
   * 	  back to zero to indicate that it is free.
   * 	- Remove unused entries in segment table and page tables of
   * 	  the process [proc].
   * 	- Remember to use lock to protect the memory from other
   * 	  processes.  */
  pthread_mutex_lock (&mem_lock);
  addr_t p_addr;

  // check if virtual address is valid
  if (translate (address, &p_addr, proc) != 1)
    {
      pthread_mutex_unlock (&mem_lock);
      return 1;
    }

  addr_t vir_addr = address;
  addr_t p_num = p_addr >> OFFSET_LEN;
  while (p_num != -1)
    {
      // update status of physical pages
      _mem_stat[p_num].proc = 0;
      _mem_stat[p_num].index = -1;
      int next_p = _mem_stat[p_num].next;
      _mem_stat[p_num].next = -1;
      p_num = next_p;

      // update page_table
      addr_t first_lev = get_first_lv (vir_addr);
      addr_t second_lev = get_second_lv (vir_addr);
      struct page_table_t *page_table
          = get_page_table (first_lev, proc->seg_table);

      page_table->table[second_lev].v_index = -1;
      page_table->table[second_lev].p_index = -1;
      page_table->size--;

      vir_addr += PAGE_SIZE;
    }

  // Move up bp (if possible)
  if (vir_addr == proc->bp)
    {
      proc->bp = address;
      while (proc->bp != 0)
        {
          addr_t prev = proc->bp - PAGE_SIZE;
          addr_t first_lev = get_first_lv (prev);
          addr_t second_lev = get_second_lv (prev);

          struct page_table_t *page_table
              = get_page_table (first_lev, proc->seg_table);
          if (page_table->table[second_lev].v_index == -1)
            proc->bp = prev;
          else
            break;
        }
    }

  // Clean up empty page table
  for (int i = proc->seg_table->size - 1; i >= 0; --i)
    {
      struct page_table_t *page_table = get_page_table (i, proc->seg_table);

      // Stop if page_table isn't empty
      if (page_table->size > 0)
        break;

      free (proc->seg_table->table[i].pages);
      proc->seg_table->table[i].pages = NULL;
      proc->seg_table->size--;
    }

  pthread_mutex_unlock (&mem_lock);
  return 0;
}

int
read_mem (addr_t address, struct pcb_t *proc, BYTE *data)
{
  addr_t physical_addr;
  if (translate (address, &physical_addr, proc))
    {
      *data = _ram[physical_addr];
      return 0;
    }
  else
    {
      return 1;
    }
}

int
write_mem (addr_t address, struct pcb_t *proc, BYTE data)
{
  addr_t physical_addr;
  if (translate (address, &physical_addr, proc))
    {
      _ram[physical_addr] = data;
      return 0;
    }
  else
    {
      return 1;
    }
}

void
dump (void)
{
  int i;
  for (i = 0; i < NUM_PAGES; i++)
    {
      if (_mem_stat[i].proc != 0)
        {
          printf ("%03d: ", i);
          printf ("%05x-%05x - PID: %02d (idx %03d, nxt: %03d)\n",
                  i << OFFSET_LEN, ((i + 1) << OFFSET_LEN) - 1,
                  _mem_stat[i].proc, _mem_stat[i].index, _mem_stat[i].next);
          int j;
          for (j = i << OFFSET_LEN; j < ((i + 1) << OFFSET_LEN) - 1; j++)
            {

              if (_ram[j] != 0)
                {
                  printf ("\t%05x: %02x\n", j, _ram[j]);
                }
            }
        }
    }
}
