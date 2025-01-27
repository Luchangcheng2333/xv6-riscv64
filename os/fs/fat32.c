#include "param.h"
#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "buf.h"
#include "proc.h"
#include "stat.h"
#include "fat32.h"

static struct {
    uint32  first_data_sec;
    uint32  data_sec_cnt;
    uint32  data_clus_cnt;
    uint32  byts_per_clus;

    struct {
        uint16  byts_per_sec;
        uint8   sec_per_clus;
        uint16  rsvd_sec_cnt;
        uint8   fat_cnt;            /* count of FAT regions */
        uint32  hidd_sec;           /* count of hidden sectors */
        uint32  tot_sec;            /* total count of sectors including all regions */
        uint32  fat_sz;             /* count of sectors for a FAT region */
        uint32  root_clus;
    } bpb;

} fat;

static struct entry_cache {
    struct spinlock lock;
    struct dirent entries[ENTRY_CACHE_NUM];
} ecache;

struct dirent root;

/**
 * Read the Boot Parameter Block.
 * @return  0       if success
 *          -1      if fail
 */
int fat32_init()
{
    #ifdef DEBUG
    printf("[fat32_init] enter!\n");
    #endif
    struct buf *b = bread(0, 0);

    
    if (strncmp((char const*)(b->data + 82), "FAT32", 5))
    {
        printf("%s\n", b->data);
        panic("not FAT32 volume");
    }
    

    // fat.bpb.byts_per_sec = *(uint16 *)(b->data + 11);
    memmove(&fat.bpb.byts_per_sec, b->data + 11, 2);            // avoid misaligned load on k210
    fat.bpb.sec_per_clus = *(b->data + 13);
    fat.bpb.rsvd_sec_cnt = *(uint16 *)(b->data + 14);
    fat.bpb.fat_cnt = *(b->data + 16);
    fat.bpb.hidd_sec = *(uint32 *)(b->data + 28);
    fat.bpb.tot_sec = *(uint32 *)(b->data + 32);
    fat.bpb.fat_sz = *(uint32 *)(b->data + 36);
    fat.bpb.root_clus = *(uint32 *)(b->data + 44);
    fat.first_data_sec = fat.bpb.rsvd_sec_cnt + fat.bpb.fat_cnt * fat.bpb.fat_sz;
    fat.data_sec_cnt = fat.bpb.tot_sec - fat.first_data_sec;
    fat.data_clus_cnt = fat.data_sec_cnt / fat.bpb.sec_per_clus;
    fat.byts_per_clus = fat.bpb.sec_per_clus * fat.bpb.byts_per_sec;
    brelse(b);

    #ifdef DEBUG
    printf("[FAT32 init]byts_per_sec: %d\n", fat.bpb.byts_per_sec);
    printf("[FAT32 init]root_clus: %d\n", fat.bpb.root_clus);
    printf("[FAT32 init]sec_per_clus: %d\n", fat.bpb.sec_per_clus);
    printf("[FAT32 init]fat_cnt: %d\n", fat.bpb.fat_cnt);
    printf("[FAT32 init]fat_sz: %d\n", fat.bpb.fat_sz);
    printf("[FAT32 init]first_data_sec: %d\n", fat.first_data_sec);
    #endif

    // make sure that byts_per_sec has the same value with BSIZE 
    if (BSIZE != fat.bpb.byts_per_sec) 
        panic("byts_per_sec != BSIZE");
    
    initlock(&ecache.lock, "ecache");
    memset(&root, 0, sizeof(root));
    initsleeplock(&root.lock, "entry");
    root.attribute = (ATTR_DIRECTORY | ATTR_SYSTEM);
    root.first_clus = root.cur_clus = fat.bpb.root_clus;
    root.valid = 1;
    root.prev = &root;
    root.next = &root;
    for(struct dirent *de = ecache.entries; de < ecache.entries + ENTRY_CACHE_NUM; de++) {
        de->dev = 0;
        de->valid = 0;
        de->ref = 0;
        de->dirty = 0;
        de->parent = 0;
        de->next = root.next;
        de->prev = &root;
        initsleeplock(&de->lock, "entry");
        root.next->prev = de;
        root.next = de;
    }
    
    return 0;
}

/**
 * @param   cluster   cluster number starts from 2, which means no 0 and 1
 */
static inline uint32 first_sec_of_clus(uint32 cluster)
{
    return ((cluster - 2) * fat.bpb.sec_per_clus) + fat.first_data_sec;
}

/**
 * For the given number of a data cluster, return the number of the sector in a FAT table.
 * @param   cluster     number of a data cluster
 * @param   fat_num     number of FAT table from 1, shouldn't be larger than bpb::fat_cnt
 */
static inline uint32 fat_sec_of_clus(uint32 cluster, uint8 fat_num)
{
    return fat.bpb.rsvd_sec_cnt + (cluster << 2) / fat.bpb.byts_per_sec + fat.bpb.fat_sz * (fat_num - 1);
}

/**
 * For the given number of a data cluster, return the offest in the corresponding sector in a FAT table.
 * @param   cluster   number of a data cluster
 */
static inline uint32 fat_offset_of_clus(uint32 cluster)
{
    return (cluster << 2) % fat.bpb.byts_per_sec;
}

/**
 * Read the FAT table content corresponded to the given cluster number.
 * @param   cluster     the number of cluster which you want to read its content in FAT table
 */
static uint32 read_fat(uint32 cluster)
{
    if (cluster >= FAT32_EOC) {
        return cluster;
    }
    if (cluster > fat.data_clus_cnt + 1) {     // because cluster number starts at 2, not 0
        return 0;
    }
    uint32 fat_sec = fat_sec_of_clus(cluster, 1);
    // here should be a cache layer for FAT table, but not implemented yet.
    struct buf *b = bread(0, fat_sec);
    uint32 next_clus = *(uint32 *)(b->data + fat_offset_of_clus(cluster));
    brelse(b);
    return next_clus;
}

/**
 * Write the FAT region content corresponded to the given cluster number.
 * @param   cluster     the number of cluster to write its content in FAT table
 * @param   content     the content which should be the next cluster number of FAT end of chain flag
 */
static int write_fat(uint32 cluster, uint32 content)
{
    if (cluster > fat.data_clus_cnt + 1) {
        return -1;
    }
    uint32 fat_sec = fat_sec_of_clus(cluster, 1);
    struct buf *b = bread(0, fat_sec);
    uint off = fat_offset_of_clus(cluster);
    *(uint32 *)(b->data + off) = content;
    bwrite(b);
    brelse(b);
    return 0;
}

static void zero_clus(uint32 cluster)
{
    uint32 sec = first_sec_of_clus(cluster);
    struct buf *b;
    for (int i = 0; i < fat.bpb.sec_per_clus; i++) {
        b = bread(0, sec++);
        memset(b->data, 0, BSIZE);
        bwrite(b);
        brelse(b);
    }
}

static uint32 alloc_clus(uint8 dev)
{
    // should we keep a free cluster list? instead of searching fat every time.
    struct buf *b;
    uint32 sec = fat.bpb.rsvd_sec_cnt;
    uint32 const ent_per_sec = fat.bpb.byts_per_sec / sizeof(uint32);
    for (uint32 i = 0; i < fat.bpb.fat_sz; i++, sec++) {
        b = bread(dev, sec);
        for (uint32 j = 0; j < ent_per_sec; j++) {
            if (((uint32 *)(b->data))[j] == 0) {
                ((uint32 *)(b->data))[j] = FAT32_EOC + 7;
                bwrite(b);
                brelse(b);
                uint32 clus = i * ent_per_sec + j;
                zero_clus(clus);
                return clus;
            }
        }
        brelse(b);
    }
    panic("no clusters");
}

static void free_clus(uint32 cluster)
{
    write_fat(cluster, 0);
}

static uint rw_clus(uint32 cluster, int write, int user, uint64 data, uint off, uint n)
{
    if (off + n > fat.byts_per_clus)
        panic("offset out of range");
    uint tot, m;
    struct buf *bp;
    uint sec = first_sec_of_clus(cluster) + off / fat.bpb.byts_per_sec;
    off = off % fat.bpb.byts_per_sec;

    int bad = 0;
    for (tot = 0; tot < n; tot += m, off += m, data += m, sec++) {
        bp = bread(0, sec);
        m = BSIZE - off % BSIZE;
        if (n - tot < m) {
            m = n - tot;
        }
        if (write) {
            if ((bad = either_copyin(bp->data + (off % BSIZE), user, data, m)) != -1) {
                bwrite(bp);
            }
        } else {
            bad = either_copyout(user, data, bp->data + (off % BSIZE), m);
        }
        brelse(bp);
        if (bad == -1) {
            break;
        }
    }
    return tot;
}

/**
 * for the given entry, relocate the cur_clus field based on the off
 * @param   entry       modify its cur_clus field
 * @param   off         the offset from the beginning of the relative file
 * @param   alloc       whether alloc new cluster when meeting end of FAT chains
 * @return              the offset from the new cur_clus
 */
static uint reloc_clus(struct dirent *entry, uint off, int alloc)
{
    int clus_num = off / fat.byts_per_clus;
    while (clus_num > entry->clus_cnt) {
        int clus = read_fat(entry->cur_clus);
        if (clus >= FAT32_EOC) {
            if (alloc) {
                clus = alloc_clus(entry->dev);
                write_fat(entry->cur_clus, clus);
            } else {
                entry->cur_clus = clus;
                entry->clus_cnt = ((uint) ~0) >> 1;
                break;
            }
        }
        entry->cur_clus = clus;
        entry->clus_cnt++;
    }
    if (clus_num < entry->clus_cnt) {
        entry->cur_clus = entry->first_clus;
        entry->clus_cnt = 0;
        while (entry->clus_cnt < clus_num) {
            entry->cur_clus = read_fat(entry->cur_clus);
            if (entry->cur_clus >= FAT32_EOC) {
                panic("reloc_clus");
            }
            entry->clus_cnt++;
        }
    }
    return off % fat.byts_per_clus;
}

/* like the original readi, but "reade" is odd, let alone "writee" */
// Caller must hold entry->lock.
int eread(struct dirent *entry, int user_dst, uint64 dst, uint off, uint n)
{
    if (off > entry->file_size || off + n < off || (entry->attribute & ATTR_DIRECTORY)) {
        return 0;
    }
    if (off + n > entry->file_size) {
        n = entry->file_size - off;
    }

    uint tot, m;
    for (tot = 0; entry->cur_clus < FAT32_EOC && tot < n; tot += m, off += m, dst += m) {
        reloc_clus(entry, off, 0);
        m = fat.byts_per_clus - off % fat.byts_per_clus;
        if (n - tot < m) {
            m = n - tot;
        }
        if (rw_clus(entry->cur_clus, 0, user_dst, dst, off % fat.byts_per_clus, m) != m) {
            break;
        }
    }
    return tot;
}

// Caller must hold entry->lock.
int ewrite(struct dirent *entry, int user_src, uint64 src, uint off, uint n)
{
    if (off > entry->file_size || off + n < off || (entry->attribute & ATTR_READ_ONLY)) {
        return -1;
    }
    if (entry->first_clus == 0) {   // so file_size if 0 too, which requests off == 0
        entry->cur_clus = entry->first_clus = alloc_clus(entry->dev);
        entry->clus_cnt = 0;
        entry->dirty = 1;
    }
    uint tot, m;
    for (tot = 0; tot < n; tot += m, off += m, src += m) {
        reloc_clus(entry, off, 1);
        m = fat.byts_per_clus - off % fat.byts_per_clus;
        if (n - tot < m) {
            m = n - tot;
        }
        if (rw_clus(entry->cur_clus, 1, user_src, src, off % fat.byts_per_clus, m) != m) {
            break;
        }
    }
    if(n > 0) {
        if(off > entry->file_size) {
            entry->file_size = off;
            entry->dirty = 1;
            // eupdate(entry);
        }
    }
    return tot;
}

// Returns a dirent struct. If name is given, check ecache. It is difficult to cache entries
// by their whole path. But when parsing a path, we open all the directories through it, 
// which forms a linked list from the final file to the root. Thus, we use the "parent" pointer 
// to recognize whether an entry with the "name" as given is really the file we want in the right path.
// Should never get root by eget, it's easy to understand.
static struct dirent *eget(struct dirent *parent, char *name)
{
    struct dirent *ep;
    acquire(&ecache.lock);
    if (name) {
        for (ep = root.next; ep != &root; ep = ep->next) {          // LRU algo
            if (ep->valid == 1 && ep->parent == parent
                && strncmp(ep->filename, name, FAT32_MAX_FILENAME) == 0) {
                ep->ref++;
                release(&ecache.lock);
                edup(ep->parent);
                return ep;
            }
        }
    }
    for (ep = root.prev; ep != &root; ep = ep->prev) {              // LRU algo
        if (ep->ref == 0) {
            ep->ref = 1;
            ep->dev = parent->dev;
            ep->off = 0;
            ep->valid = 0;
            release(&ecache.lock);
            return ep;
        }
    }
    panic("eget: insufficient ecache");
    return 0;
}

// trim ' ' in the head and tail, '.' in head, and test legality
static char *formatname(char *name)
{
    static char illegal[] = { '\"', '*', '/', ':', '<', '>', '?', '\\', '|' };
    char *p;
    while (*name == ' ' || *name == '.') { name++; }
    for (p = name; *p; p++) {
        char c = *p;
        if (c < ' ') { return 0; }
        for (int i = 0; i < sizeof(illegal); i++) {
            if (c == illegal[i]) { return 0; }
        }
    }
    while (p-- > name) {
        if (*p != ' ') {
            p[1] = '\0';
            break;
        }
    }
    return name;
}

static void generate_shortname(char *shortname, char *name)
{
    static char illegal[] = { '+', ',', ';', '=', '[', ']' };   // these are legal in l-n-e but not s-n-e
    int i = 0;
    char c, *p = name;
    for (int j = strlen(name) - 1; j >= 0; j--) {
        if (name[j] == '.') {
            p = name + j;
            break;
        }
    }
    while (i < CHAR_SHORT_NAME && (c = *name++)) {
        if (i == 8 && p) {
            if (p + 1 < name) { break; }            // no '.'
            else {
                name = p + 1, p = 0;
                continue;
            }
        }
        if (c == ' ') { continue; }
        if (c == '.') {
            if (name > p) {                    // last '.'
                memset(shortname + i, ' ', 8 - i);
                i = 8, p = 0;
            }
            continue;
        }
        if (c >= 'a' && c <= 'z') {
            c += 'A' - 'a';
        } else {
            for (int j = 0; j < sizeof(illegal); j++) {
                if (c == illegal[j]) {
                    c = '_';
                    break;
                }
            }
        }
        shortname[i++] = c;
    }
    while (i < CHAR_SHORT_NAME) {
        shortname[i++] = ' ';
    }
}

uint8 cal_checksum(uchar* shortname)
{
    uint8 sum = 0;
    for (int i = CHAR_SHORT_NAME; i != 0; i--) {
        sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + *shortname++;
    }
    return sum;
}

/**
 * Generate an entry in the raw type and write to the disk.
 * @param   data        for s-n-e it's the first cluster, for l-n-e it's the ordinal.
 * @param   checksum    only for l-n-e, the checksum.
 */
static void make_entry(struct dirent *dp, uint off, char *name, uint8 attr, uint32 data, uint8 checksum)
{
    uint8 ebuf[32] = {0};
    if ((ebuf[11] = attr) == ATTR_LONG_NAME) {
        ebuf[0] = data;
        ebuf[13] = checksum;
        name += ((data & ~LAST_LONG_ENTRY) - 1) * CHAR_LONG_NAME;
        uint8 *w = ebuf + 1;
        int end = 0;
        for (int i = 1; i <= CHAR_LONG_NAME; i++) {
            if (end) {
                *w++ = 0xff;            // on k210, unaligned reading is illegal
                *w++ = 0xff;
            } else { 
                if ((*w++ = *name++) == 0) {
                    end = 1;
                }
                *w++ = 0;
            }
            switch (i) {
                case 5:     w = ebuf + 14; break;
                case 11:    w = ebuf + 28; break;
            }
        }
    } else {
        strncpy((char *)ebuf, name, 11);
        *(uint16 *)(ebuf + 20) = (uint16)(data >> 16);      // first clus high 16 bits
        *(uint16 *)(ebuf + 26) = (uint16)(data & 0xff);     // low 16 bits
        *(uint32 *)(ebuf + 28) = 0;                         // filesize is updated in eupdate()
    }
    off = reloc_clus(dp, off, 1);
    rw_clus(dp->cur_clus, 1, 0, (uint64)ebuf, off, sizeof(ebuf));
}

/**
 * Allocate an entry on disk. Caller must hold dp->lock.
 */
struct dirent *ealloc(struct dirent *dp, char *name, int dir)
{
    if (!(dp->attribute & ATTR_DIRECTORY)) {
        panic("ealloc not dir");
    }
    if (!(name = formatname(name))) {        // detect illegal character
        return 0;
    }
    struct dirent *ep;
    uint off = 0;
    if ((ep = dirlookup(dp, name, &off)) != 0) {      // entry exists
        eput(ep);
        return 0;
    }
    ep = eget(dp, name);
    if (ep->valid) {    // shouldn't be valid
        panic("ealloc");
    }
    elock(ep);
    ep->attribute = 0;
    ep->file_size = 0;
    ep->first_clus = 0;
    ep->parent = edup(dp);
    ep->off = off;
    ep->clus_cnt = 0;
    ep->cur_clus = 0;
    ep->dirty = 0;
    strncpy(ep->filename, name, FAT32_MAX_FILENAME);    

    int entcnt = (strlen(name) + CHAR_LONG_NAME - 1) / CHAR_LONG_NAME;   // count of l-n-entries, rounds up
    if (dir) {    // generate "." and ".." for ep
        ep->attribute |= ATTR_DIRECTORY;
        ep->cur_clus = ep->first_clus = alloc_clus(dp->dev);
        make_entry(ep, 0, ".", ATTR_DIRECTORY, ep->first_clus, 0);
        make_entry(ep, 32, "..", ATTR_DIRECTORY, dp->first_clus, 0);
    } else {
        ep->attribute |= ATTR_ARCHIVE;
    }
    char shortname[CHAR_SHORT_NAME + 1] = {0};
    generate_shortname(shortname, name);
    uint8 checksum = cal_checksum((uchar *)shortname);
    for (int i = entcnt; i > 0; i--) {
        int longnum = i;
        if (i == entcnt) {
            longnum |= LAST_LONG_ENTRY;
        }
        make_entry(dp, off, ep->filename, ATTR_LONG_NAME, longnum, checksum);
        off += 32;
    }
    make_entry(dp, off, shortname, ep->attribute, ep->first_clus, 0);
    ep->valid = 1;
    eunlock(ep);
    return ep;
}

struct dirent *edup(struct dirent *entry)
{
    if (entry != 0) {
        acquire(&ecache.lock);
        //printf("breakpoint 1 done\n");
        entry->ref++;
        release(&ecache.lock);
    }
    return entry;
}

// Only update filesize and first cluster in this case.
void eupdate(struct dirent *entry)
{
    if (!entry->dirty) { return; }
    uint entcnt;
    uint32 off = reloc_clus(entry->parent, entry->off, 0);
    rw_clus(entry->parent->cur_clus, 0, 0, (uint64) &entcnt, off, 1);
    entcnt &= ~LAST_LONG_ENTRY;
    off = reloc_clus(entry->parent, entry->off + (entcnt << 5), 0);
    uint16 clus_high = (uint16)(entry->first_clus >> 16);
    uint16 clus_low = (uint16)(entry->first_clus & 0xff);
    rw_clus(entry->parent->cur_clus, 1, 0, (uint64) &clus_high, off + 20, sizeof(uint16));
    rw_clus(entry->parent->cur_clus, 1, 0, (uint64) &clus_low, off + 26, sizeof(uint16));
    rw_clus(entry->parent->cur_clus, 1, 0, (uint64) &entry->file_size, off + 28, sizeof(entry->file_size));
    entry->dirty = 0;
}

// delete a file
void etrunc(struct dirent *entry)
{
    uint entcnt;
    elock(entry->parent);
    uint32 off = entry->off;
    uint32 off2 = reloc_clus(entry->parent, off, 0);
    rw_clus(entry->parent->cur_clus, 0, 0, (uint64) &entcnt, off2, 1);
    entcnt &= ~LAST_LONG_ENTRY;
    uint8 flag = EMPTY_ENTRY;
    for (int i = 0; i <= entcnt; i++) {
        rw_clus(entry->parent->cur_clus, 1, 0, (uint64) &flag, off2, 1);
        off += 32;
        off2 = reloc_clus(entry->parent, off, 0);
    }
    eunlock(entry->parent);
    entry->valid = 0;
    for (uint32 clus = entry->first_clus; clus >= 2 && clus < FAT32_EOC; ) {
        uint32 next = read_fat(clus);
        free_clus(clus);
        clus = next;
    }
}

void elock(struct dirent *entry)
{
    if (entry == 0 || entry->ref < 1)
        panic("elock");
    acquiresleep(&entry->lock);
}

void eunlock(struct dirent *entry)
{
    if (entry == 0 || !holdingsleep(&entry->lock) || entry->ref < 1)
        panic("eunlock");
    releasesleep(&entry->lock);
}

void eput(struct dirent *entry)
{
    acquire(&ecache.lock);
    if (entry->valid && entry->ref == 1) {
        // ref == 1 means no other process can have entry locked,
        // so this acquiresleep() won't block (or deadlock).
        acquiresleep(&entry->lock);
        release(&ecache.lock);
        if (entry != &root) {
            entry->next->prev = entry->prev;
            entry->prev->next = entry->next;
            entry->next = root.next;
            entry->prev = &root;
            root.next->prev = entry;
            root.next = entry;
            if (entry->valid == 2) {
                etrunc(entry);
            } else {
                eupdate(entry);
            }
            eput(entry->parent);
        }
        releasesleep(&entry->lock);
        acquire(&ecache.lock);
    }
    entry->ref--;
    release(&ecache.lock);
}

void estat(struct dirent *entry, struct stat *st)
{
    strncpy(st->name, entry->filename, STAT_MAX_NAME);
    st->type = (entry->attribute & ATTR_DIRECTORY) ? T_DIR : T_FILE;
    st->dev = entry->dev;
    st->size = entry->file_size;
}

/**
 * Read filename from directory entry.
 * @param   buffer      pointer to the array that stores the name
 * @param   raw_entry   pointer to the entry in a sector buffer
 * @param   islong      if non-zero, read as l-n-e, otherwise s-n-e.
 */
static void read_entry_name(char *buffer, uint8 *raw_entry, int islong)
{
    if (islong) {                       // long entry branch
        wchar temp[10];
        memmove(temp, raw_entry + 1, 10);
        snstr(buffer, temp, 5);
        snstr(buffer + 5, (wchar *) (raw_entry + 14), 6);
        snstr(buffer + 11, (wchar *) (raw_entry + 28), 2);
    } else {
        // assert: only "." and ".." will enter this branch
        memset(buffer, 0, 12);
        int i = 7;
        if (raw_entry[i] == ' ') {
            do {
                i--;
            } while (i >= 0 && raw_entry[i] == ' ');
        }
        i++;
        memmove(buffer, raw_entry, i);
        if (raw_entry[8] != ' ') {
            memmove(buffer + i + 1, raw_entry + 8, 3);
            buffer[i] = '.';
        }
    }
}

/**
 * Read entry_info from directory entry.
 * @param   entry       pointer to the structure that stores the entry info
 * @param   raw_entry   pointer to the entry in a sector buffer
 */
static void read_entry_info(struct dirent *entry, uint8 *raw_entry)
{
    entry->attribute = raw_entry[11];
    // entry->create_time_tenth = raw_entry[13];
    // entry->create_time = *(uint16 *)(raw_entry + 14);
    // entry->create_date = *(uint16 *)(raw_entry + 16);
    // entry->last_access_date = *(uint16 *)(raw_entry + 18);
    // entry->last_write_time = *(uint16 *)(raw_entry + 22);
    // entry->last_write_date = *(uint16 *)(raw_entry + 24);
    entry->first_clus = ((uint32) *(uint16 *)(raw_entry + 20)) << 16;
    entry->first_clus += *(uint16 *)(raw_entry + 26);
    entry->file_size = *(uint32 *)(raw_entry + 28);
    entry->cur_clus = entry->first_clus;
    entry->clus_cnt = 0;
}

/**
 * Read a directory from off, parse the next entry(ies) associated with one file, or find empty entry slots.
 * Caller must hold dp->lock.
 * @param   dp      the directory
 * @param   ep      the struct to be written with info
 * @param   off     offset off the directory
 * @param   count   to write the count of entries
 * @return  -1      meet the end of dir
 *          0       find empty slots
 *          1       find a file with all its entries
 */
int enext(struct dirent *dp, struct dirent *ep, uint off, int *count)
{
    if (!(dp->attribute & ATTR_DIRECTORY))
        panic("enext not dir");
    if (ep->valid)
        panic("enext ep valid");
    if (off % 32)
        panic("enext not align");

    uint8 ebuf[32];
    int cnt = 0;
    memset(ep->filename, 0, FAT32_MAX_FILENAME + 1);
    uint off2 = reloc_clus(dp, off, 0);
    for (; dp->cur_clus < FAT32_EOC; off += 32, off2 = reloc_clus(dp, off, 0)) {
        if (rw_clus(dp->cur_clus, 0, 0, (uint64)ebuf, off2, 32) != 32 || ebuf[0] == END_OF_ENTRY) {
            return -1;
        }
        if (ebuf[0] == EMPTY_ENTRY) {
            cnt++;
            continue;
        } else if (cnt) {
            *count = cnt;
            return 0;
        }
        if (ebuf[11] == ATTR_LONG_NAME) {
            int lcnt = ebuf[0] & ~LAST_LONG_ENTRY;
            if (ebuf[0] & LAST_LONG_ENTRY) {
                *count = lcnt + 1;                              // plus the s-n-e;
                count = 0;
            }
            read_entry_name(ep->filename + (lcnt - 1) * CHAR_LONG_NAME, ebuf, 1);
        } else {
            if (count) {
                *count = 1;
                read_entry_name(ep->filename, ebuf, 0);
            }
            read_entry_info(ep, ebuf);
            return 1;
        }
    }
    return -1;
}

/**
 * Seacher for the entry in a directory and return a structure. Besides, record the offset of
 * some continuous empty slots that can fit the length of filename.
 * Caller must hold entry->lock.
 * @param   dp          entry of a directory file
 * @param   filename    target filename
 * @param   poff        offset of proper empty entry slots from the beginning of the dir
 */
struct dirent *dirlookup(struct dirent *dp, char *filename, uint *poff)
{
    if (!(dp->attribute & ATTR_DIRECTORY))
        panic("dirlookup not DIR");
    if (strncmp(filename, ".", FAT32_MAX_FILENAME) == 0) {
        return edup(dp);
    } else if (strncmp(filename, "..", FAT32_MAX_FILENAME) == 0) {
        return edup(dp->parent);
    }
    struct dirent *ep = eget(dp, filename);
    if (ep->valid) { return ep; }                               // ecache hits

    int len = strlen(filename);
    int entcnt = (len + CHAR_LONG_NAME - 1) / CHAR_LONG_NAME + 1;   // count of l-n-entries, rounds up. plus s-n-e
    int count = 0;
    int type;
    uint off = 0;
    reloc_clus(dp, 0, 0);
    while ((type = enext(dp, ep, off, &count) != -1)) {
        if (type == 0) {
            if (poff && count >= entcnt) {
                *poff = off;
                poff = 0;
            }
        } else if (strncmp(filename, ep->filename, FAT32_MAX_FILENAME) == 0) {
            ep->parent = edup(dp);
            ep->off = off;
            ep->valid = 1;
            return ep;
        }
        off += count << 5;
    }
    if (poff) {
        *poff = off;
    }
    eput(ep);
    return 0;
}

static char *skipelem(char *path, char *name)
{
    while (*path == '/') {
        path++;
    }
    if (*path == 0) { return 0; }
    char *s = path;
    while (*path != '/' && *path != 0) {
        path++;
    }
    int len = path - s;
    if (len > FAT32_MAX_FILENAME) {
        len = FAT32_MAX_FILENAME;
    } else {
        name[len] = 0;
    }
    memmove(name, s, len);
    while (*path == '/') {
        path++;
    }
    return path;
}

// FAT32 version of namex in xv6's original file system.
static struct dirent *lookup_path(char *path, int parent, char *name)
{
    struct dirent *entry, *next;
    if (*path == '/') {
        entry = edup(&root);
    } else {
        entry = edup(myproc()->cwd);
    }
    
    while ((path = skipelem(path, name)) != 0) {
        elock(entry);
        if (!(entry->attribute & ATTR_DIRECTORY)) {
            eunlock(entry);
            eput(entry);
            return 0;
        }
        if (parent && *path == '\0') {
            eunlock(entry);
            return entry;
        }
        if ((next = dirlookup(entry, name, 0)) == 0) {
            eunlock(entry);
            eput(entry);
            return 0;
        }
        eunlock(entry);
        eput(entry);
        entry = next;
    }
    if (parent) {
        eput(entry);
        return 0;
    }
    return entry;
}


struct dirent *ename(char *path)
{
    /*
    for (int i = 0; i < MAXMAPFILES; i++)
    {
        if (mount_list[i] != NULL && !strncmp(path, mount_list[i]->target_ep->filename, FAT32_MAX_FILENAME + 1))
        {
            return mount_list[i]->origin_ep;
        }
    }
    */

    char name[FAT32_MAX_FILENAME + 1] = {0};
    return lookup_path(path, 0, name);
}

struct dirent *enameparent(char *path, char *name)
{
    /*
    for (int i = 0; i < MAXMAPFILES; i++)
    {
        if (mount_list[i] != NULL && !strncmp(path, mount_list[i]->target_ep->filename, FAT32_MAX_FILENAME + 1))
        {
            return mount_list[i]->origin_ep;
        }
    }
    */

    return lookup_path(path, 1, name);
}
