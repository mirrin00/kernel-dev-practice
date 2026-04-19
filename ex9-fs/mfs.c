#include "linux/bitmap.h"
#include "linux/bitops.h"
#include "linux/blk_types.h"
#include "linux/blkdev.h"
#include "linux/buffer_head.h"
#include "linux/build_bug.h"
#include "linux/byteorder/generic.h"
#include "linux/container_of.h"
#include "linux/dcache.h"
#include "linux/errno.h"
#include "linux/fs.h"
#include "linux/fs_types.h"
#include "linux/writeback.h"
#include "linux/gfp_types.h"
#include "linux/init.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include "linux/stat.h"
#include "linux/timekeeping.h"
#include "linux/types.h"
#include "linux/mpage.h"
#include <linux/module.h>

// Macros for logging
#define MOD_PRFX "mfs: "
#define MOD_DEBUG(fmt, ...) pr_debug(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_INFO(fmt, ...) pr_info(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_WARN(fmt, ...) pr_warn(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_ERR(fmt, ...) pr_err(MOD_PRFX fmt "\n", ##__VA_ARGS__)

// Offsets in bytes
#define MFS_SB_OFFSET_BYTES (4096lu)
#define MFS_SB_SIZE_BYTES (4096lu)
#define MFS_MD_OFFSET_BYTES (MFS_SB_OFFSET_BYTES + MFS_SB_SIZE_BYTES)
#define MFS_MD_SIZE_BYTES (4096lu)
#define MFS_DATA_OFFSET_BYTES (MFS_MD_OFFSET_BYTES + MFS_MD_SIZE_BYTES)
// Offsets in sectors
#define MFS_SB_OFFSET (MFS_SB_OFFSET_BYTES >> SECTOR_SHIFT)
#define MFS_MD_OFFSET (MFS_MD_OFFSET_BYTES >> SECTOR_SHIFT)
#define MFS_DATA_OFFSET (MFS_DATA_OFFSET_BYTES >> SECTOR_SHIFT)
// Converts bytes to blocks
#define to_blocks(size, sb) ((size) >> (sb)->s_blocksize_bits)
#define to_blocks_by_lb(size, lb) ((size) / lb)
#define MFS_DATA_START(sb) to_blocks(MFS_DATA_OFFSET_BYTES, sb)

// Constants
#define MFS_MAX_INODES (32)
#define MFS_MAX_FILENAME (16)

#if MFS_MAX_INODES >= 8
    #if MFS_MAX_INODES % 8 == 0
        #define MFS_MAP_SIZE (MFS_MAX_INODES / 8)
    #else // % 8 == 0
        #define MFS_MAP_SIZE (MFS_MAX_INODES / 8 + 1)
    #endif
#else // >= 8
    #define MFS_MAP_SIZE (1)
#endif

#define MFS_MAGIC (0x11223344)

/**
 * Superblock
 */
struct mfs_sb {
    u8 version;
    u8 __reserved[7];
    __le64 magic;
    // Keep inode map last in sb
    u8 inode_map[MFS_MAP_SIZE];
};

static_assert(sizeof(struct mfs_sb) <= MFS_SB_SIZE_BYTES);
static_assert(sizeof(struct mfs_sb) == 24);

/**
 * Inode information on the disk
 */
struct mfs_inode_disk {
    __le16 i_mode;
    __le16 i_nlinks; // zero == empty ino
    __le16 i_uid;
    __le16 i_gid;
    __le16 size;
    __le32 time; // Same time for all
};

static_assert(sizeof(struct mfs_inode_disk) * MFS_MAX_INODES <=
              MFS_MD_SIZE_BYTES);
static_assert(sizeof(struct mfs_inode_disk) == 16);

/**
 * Superblock info
 */
struct mfs_sb_info {
    struct buffer_head *sbh;
    struct mfs_sb *sb;
    struct buffer_head *mdh;
    struct mfs_inode_disk *md;
    u64 data_offset;
    uint max_files_in_dir;
    uint max_inodes;
};

#define MFS_SBI_INIT(name, sb) struct mfs_sb_info *name = sb->s_fs_info;

struct mfs_dir_entry {
    __le16 ino; // zero -- empty entry
    u8 type;
    char name[MFS_MAX_FILENAME];
};

#define MFS_DE_REG (0)
#define MFS_DE_DIR (1)

struct mfs_inode_info {
    struct inode inode;
    uint size;
    uint max_files_in_dir;
    struct buffer_head *datah;
    struct mfs_dir_entry *entries;
};

#define GET_MFS_INODE(name, inode_ptr) \
    name = container_of(inode_ptr, typeof(*name), inode);
#define MFS_INODE_INIT(name, inode_ptr) \
    struct mfs_inode_info *name = container_of(inode_ptr, typeof(*name), inode);

/**
 * Layout
 * dev 0 .. | SB_OFFSET |    MD_OFFSET    |  DATA_OFFSET   0xffff
 * fs  ??   |  sb       |  inode metadata |   file data
 * 
 * ino -> DATA_OFFSET + ino * lb_size
 */

// ==========================
// === address operations ===
// ==========================

/**
 *  maps the file @iblock sector to the dev
 *  Ignore @create argument, placement is predefined
 */
static int mfs_map_block(struct inode *inode, sector_t iblock,
                         struct buffer_head *bh_result, int create)
{
    ulong m_ino = inode->i_ino - 1;
    struct super_block *sb = inode->i_sb;

    MOD_DEBUG("Map is called for m_ino=%lu res=%lu", m_ino,
              MFS_DATA_START(sb) + m_ino);
    map_bh(bh_result, sb, MFS_DATA_START(sb) + m_ino);
    return 0;
}

// from dev to cache
static int mfs_read_folio(struct file *filp, struct folio *folio)
{
    MOD_DEBUG("Read page folio is called");
    return block_read_full_folio(folio, mfs_map_block);
}

// from cache to dev
static int mfs_writepages(struct address_space *mapping,
                          struct writeback_control *wbc)
{
    MOD_DEBUG("write pages is called");
    return mpage_writepages(mapping, wbc, mfs_map_block);
}

// From file to cache
static int mfs_write_begin(struct file *filp, struct address_space *mapping,
                           loff_t pos, unsigned len, struct folio **foliop,
                           void **fsdata)
{
    MOD_DEBUG("write begin is called");
    MOD_DEBUG("isize before %llu", file_inode(filp)->i_size);
    int err = block_write_begin(mapping, pos, len, foliop, mfs_map_block);
    return err;
}

// After write
static int mfs_write_end(struct file *filp, struct address_space *mapping,
                         loff_t pos, unsigned len, unsigned copied,
                         struct folio *foliop, void *fsdata)
{
    MOD_DEBUG("write end is called, copied %u", copied);
    return generic_write_end(filp, mapping, pos, len, copied, foliop, fsdata);
}

static sector_t mfs_bmap(struct address_space *mapping, sector_t block)
{
    MOD_DEBUG("bmap is called");
    return generic_block_bmap(mapping, block, mfs_map_block);
}

static const struct address_space_operations mfs_asop = {
    .read_folio = mfs_read_folio,
    .writepages = mfs_writepages,
    .write_begin = mfs_write_begin,
    .write_end = mfs_write_end,
    .bmap = mfs_bmap,
    .direct_IO = noop_direct_IO,
};

// ========================
// === files operations ===
// ========================

static const struct file_operations mfs_file_ops = {
    .owner = THIS_MODULE,
    .llseek = generic_file_llseek,
    .read_iter = generic_file_read_iter,
    .write_iter = generic_file_write_iter,
    .mmap = generic_file_mmap,
    .fsync = generic_file_fsync,
};

static int __load_dir(struct mfs_inode_info *inode_info);

static uint __get_type(u8 mfs_type)
{
    switch (mfs_type) {
    case MFS_DE_REG:
        return DT_REG;
    case MFS_DE_DIR:
        return DT_DIR;
    }

    return DT_UNKNOWN;
}

static int mfs_inter_dir(struct file *filp, struct dir_context *ctx)
{
    struct inode *inode = file_inode(filp);
    struct mfs_inode_info *inode_info =
            container_of(inode, typeof(*inode_info), inode);
    struct super_block *sb = inode->i_sb;
    MFS_SBI_INIT(msbi, sb);
    int err;

    if (!S_ISDIR(inode->i_mode)) {
        MOD_ERR("Is not a dir, ino %lu", inode->i_ino);
        return -ENOTDIR;
    }

    if ((err = __load_dir(inode_info)))
        return err;

    if (!dir_emit_dots(filp, ctx))
        return 0;

    if (ctx->pos - 2 > inode_info->size)
        return 0;

    uint pos = ctx->pos - 2;
    uint alive = 0;
    MOD_DEBUG("iter node, ino %lu, pos %d", inode->i_ino, pos);

    for (uint i = 0; i < msbi->max_files_in_dir; i++) {
        struct mfs_dir_entry *de = inode_info->entries + i;
        ulong ino = le16_to_cpu(de->ino);
        if (!ino)
            continue;

        if (alive++ < pos) {
            MOD_DEBUG("Skipping %16s, i=%d", de->name, i);
            continue;
        }

        MOD_DEBUG("Emitting %s, ino=%lu, i=%u", de->name, ino, i);
        dir_emit(ctx, de->name, MFS_MAX_FILENAME, ino, __get_type(de->type));
        ctx->pos++;
    }

    return 0;
}

static const struct file_operations mfs_dir_ops = {
    .owner = THIS_MODULE,
    .iterate_shared = mfs_inter_dir,
};

// ========================
// === inode operations ===
// ========================

static const struct inode_operations mfs_inode_fops;
static const struct inode_operations mfs_inode_dops;

static int __set_inode_ops(struct inode *inode)
{
    if (S_ISREG(inode->i_mode)) {
        inode->i_op = &mfs_inode_fops;
        inode->i_fop = &mfs_file_ops;
        inode->i_mapping->a_ops = &mfs_asop;
    } else if (S_ISDIR(inode->i_mode)) {
        inode->i_op = &mfs_inode_dops;
        inode->i_fop = &mfs_dir_ops;
    } else {
        return -EINVAL;
    }

    return 0;
}

static struct inode *mfs_iget(struct super_block *sb, unsigned long ino)
{
    int err;
    struct inode *inode;
    struct mfs_inode_disk *dinf;
    ulong m_ino = ino - 1;
    uint nlinks;
    u32 i_time;
    MFS_SBI_INIT(msbi, sb);
    struct mfs_inode_info *inode_info;

    MOD_DEBUG("iget is called for ino=%lu", ino);

    if (!test_bit(m_ino, (void *)msbi->sb->inode_map)) {
        MOD_ERR("Not set in inode_map");
        return ERR_PTR(-ENOENT);
    }

    if (!le16_to_cpu(msbi->md[m_ino].i_nlinks)) {
        MOD_ERR("Ino is marked as not existed");
        return ERR_PTR(-ENOENT);
    }

    inode = iget_locked(sb, ino);
    if (!inode)
        return ERR_PTR(-ENOMEM);

    if (!(inode->i_state & I_NEW))
        return inode;

    dinf = msbi->md + m_ino;
    i_uid_write(inode, le16_to_cpu(dinf->i_gid));
    i_gid_write(inode, le16_to_cpu(dinf->i_gid));
    if ((nlinks = le16_to_cpu(dinf->i_nlinks))) {
        set_nlink(inode, nlinks);
    } else {
        MOD_ERR("Link is zero");
        err = -EINVAL;
        goto err;
    }

    inode->i_mode = le16_to_cpu(dinf->i_mode);
    GET_MFS_INODE(inode_info, inode);
    inode_info->size = le16_to_cpu(dinf->size);
    if (S_ISDIR(inode->i_mode)) {
        // dir size is the number of files on dir
        // set vfs size to zero
        inode->i_size = 0;
        if (inode_info->size > msbi->max_files_in_dir) {
            MOD_ERR("Too much files in dir");
            err = -ENOTSUPP;
            goto err;
        }
    } else if (S_ISREG(inode->i_mode)) {
        inode->i_size = inode_info->size;
    } else {
        MOD_ERR("Unsupported mode, ino=%lu[%lu] mode=0x%x", ino, m_ino,
                inode->i_mode);
        err = -ENOTSUPP;
        goto err;
    }

    i_time = le32_to_cpu(dinf->time);
    inode_set_ctime(inode, i_time, 0);
    inode_set_mtime(inode, i_time, 0);
    inode_set_atime(inode, i_time, 0);
    err = __set_inode_ops(inode);
    if (err)
        goto err;

    inode->i_blocks = 1;
    inode->i_sb = sb;
    inode->i_flags |= S_NOATIME;
    unlock_new_inode(inode);

    return inode;

err:
    iget_failed(inode);
    return ERR_PTR(err);
}

static int __load_dir(struct mfs_inode_info *inode_info)
{
    struct super_block *sb = inode_info->inode.i_sb;
    ulong m_ino = inode_info->inode.i_ino - 1;

    if (inode_info->datah)
        // already loaded
        return 0;

    MOD_DEBUG("Load dir, block_off=%lu m_ino=%lu blockbits=%u",
              MFS_DATA_START(sb), m_ino, sb->s_blocksize_bits);
    inode_info->datah = sb_bread(sb, MFS_DATA_START(sb) + m_ino);
    if (!inode_info->datah) {
        MOD_ERR("Failed to read inode data, ino=%lu", m_ino);
        return -EIO;
    }

    inode_info->entries = (struct mfs_dir_entry *)inode_info->datah->b_data;
    return 0;
}

static void __insert_to_dir(struct mfs_inode_info *inode_info, ulong ino,
                            const char *name, umode_t mode)
{
    u8 type = S_ISREG(mode) ? MFS_DE_REG : MFS_DE_DIR;

    for (uint i = 0; i < inode_info->max_files_in_dir; i++) {
        struct mfs_dir_entry *de = inode_info->entries + i;
        ulong cur_ino = le16_to_cpu(de->ino);

        if (cur_ino)
            continue;

        de->type = type;
        de->ino = cpu_to_le16(ino);
        strncpy(de->name, name, MFS_MAX_FILENAME);
        MOD_DEBUG("Inserted into pos i=%d, ino=%lu new_ino=%lu", i,
                  inode_info->inode.i_ino, ino);
        return;
    }

    BUG();
}

static void __inode_to_md(struct mfs_inode_info *inode_info,
                          struct mfs_inode_disk *md)
{
    struct inode *inode = &inode_info->inode;

    md->i_gid = cpu_to_le16(i_gid_read(inode));
    md->i_uid = cpu_to_le16(i_uid_read(inode));
    md->i_mode = cpu_to_le16(inode->i_mode);
    md->i_nlinks = cpu_to_le16(inode->i_nlink);
    md->time = cpu_to_le32(inode_get_ctime(inode).tv_sec);
    if (S_ISDIR(inode->i_mode)) {
        md->size = cpu_to_le16(inode_info->size);
    } else {
        md->size = cpu_to_le16(inode->i_size);
    }
}

static int mfs_create(struct mnt_idmap *idmap, struct inode *dir,
                      struct dentry *dentry, umode_t mode, bool excl)
{
    struct super_block *sb = dir->i_sb;
    MFS_INODE_INIT(dir_info, dir);
    MFS_SBI_INIT(msbi, sb);
    struct inode *inode;
    int err;
    ulong ino, m_ino;

    MOD_DEBUG("Create is called for ino=%lu", dir->i_ino);

    if (!(S_ISREG(mode) || S_ISDIR(mode)))
        return -EPERM;

    if (dentry->d_name.len >= MFS_MAX_FILENAME)
        return -ENAMETOOLONG;

    if (dir_info->size >= msbi->max_files_in_dir)
        return -ENOSPC;

    if ((err = __load_dir(dir_info)))
        return err;

    inode = new_inode(sb);
    inode_init_owner(idmap, inode, dir, mode);
    err = __set_inode_ops(inode);
    if (err) {
        MOD_ERR("Failed to setup ops");
        iput(inode);
        return err;
    }

    m_ino = find_first_zero_bit_le(msbi->sb->inode_map, MFS_MAX_INODES);
    if (m_ino >= msbi->max_inodes) {
        iput(inode);
        return -ENOSPC;
    }

    set_bit_le(m_ino, msbi->sb->inode_map);
    inode->i_ino = ino = m_ino + 1;

    set_nlink(inode, 1);
    inode->i_size = 0;
    simple_inode_init_ts(inode);

    // setup parent
    inc_nlink(dir);
    dir_info->size++;
    __insert_to_dir(dir_info, ino, dentry->d_name.name, mode);
    mark_buffer_dirty(dir_info->datah);
    mark_buffer_dirty(msbi->sbh);
    mark_inode_dirty(dir);

    insert_inode_hash(inode);
    mark_inode_dirty(inode);  // saves itself to the md later
    d_instantiate(dentry, inode);

    return 0;
}

static int mfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
                     struct dentry *dentry, umode_t mode)
{
    return mfs_create(idmap, dir, dentry, mode | S_IFDIR, false);
}

static void __remove_from_dir(struct inode *dir, ulong remove_ino)
{
    MFS_INODE_INIT(dir_info, dir);

    __load_dir(dir_info);

    for (size_t i = 0; i < dir_info->max_files_in_dir; i++) {
        struct mfs_dir_entry *de = dir_info->entries + i;

        if (le16_to_cpu(de->ino) == remove_ino) {
            memset(de, 0, sizeof(struct mfs_dir_entry));
            dir_info->size--;
            mark_buffer_dirty(dir_info->datah);
            return;
        }
    }

    MOD_WARN("Dir ino=%lu doesn't contain removing ino=%lu", dir->i_ino,
             remove_ino);
}

static int mfs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct super_block *sb = dir->i_sb;
    MFS_SBI_INIT(msbi, sb);
    struct inode *inode = d_inode(dentry);
    MFS_INODE_INIT(inode_info, inode);
    ulong ino = inode->i_ino, m_ino = ino - 1;

    if (inode->i_nlink > 1)
        return -ENOTEMPTY;

    if (S_ISDIR(inode->i_mode) && inode_info->size > 0)
        return -ENOTEMPTY;

    MOD_DEBUG("Unlink ino=%lu name=%16s", inode->i_ino, dentry->d_name.name);

    memset(msbi->md + m_ino, 0, sizeof(struct mfs_inode_disk));
    clear_bit_le(m_ino, msbi->sb->inode_map);
    __remove_from_dir(dir, ino); // + marks bh as dirty

    inode_dec_link_count(dir);
    inode_dec_link_count(inode);

    mark_inode_dirty(dir);
    mark_buffer_dirty(msbi->mdh);
    mark_buffer_dirty(msbi->sbh);

    // Task 3: file clearing

    if (inode_info->datah) {
        brelse(inode_info->datah);
        inode_info->datah = NULL;
    }

    return 0;
}

static struct dentry *mfs_lookup(struct inode *dir, struct dentry *dentry,
                                 unsigned int flags)
{
    struct mfs_inode_info *inode_info =
            container_of(dir, typeof(*inode_info), inode);
    struct super_block *sb = dir->i_sb;
    MFS_SBI_INIT(msbi, sb);
    struct inode *tgt = NULL;
    int err;

    if ((err = __load_dir(inode_info)))
        goto out;

    MOD_DEBUG("Lookup is called, for ino=%lu d_name=%s", dir->i_ino,
              dentry->d_name.name);

    for (uint i = 0; i < msbi->max_files_in_dir; i++) {
        struct mfs_dir_entry *de = inode_info->entries + i;
        ulong ino = le16_to_cpu(de->ino);
        if (ino && !strncmp(de->name, dentry->d_name.name, 16)) {
            tgt = mfs_iget(sb, ino);
            if (IS_ERR(tgt)) {
                MOD_WARN("Failed to get ino=%lu err=%ld", ino, PTR_ERR(tgt));
                tgt = NULL;
                continue;
            }

            MOD_DEBUG("lookup: found ino=%lu", ino);
            break;
        }
    }

out:
    d_add(dentry, tgt);
    return NULL;
}

static const struct inode_operations mfs_inode_dops = {
    .create = mfs_create,
    .unlink = mfs_unlink,
    .mkdir = mfs_mkdir,
    .rmdir = mfs_unlink,
    .lookup = mfs_lookup,
    .getattr = simple_getattr,
};

static const struct inode_operations mfs_inode_fops = {
    .getattr = simple_getattr,
    .setattr = simple_setattr,
};

// ==============================
// === Super block operations ===
// ==============================

struct kmem_cache *kmem_inode;

static int mfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
    struct super_block *sb = inode->i_sb;
    MFS_SBI_INIT(msbi, sb);
    MFS_INODE_INIT(inode_info, inode);

    __inode_to_md(inode_info, msbi->md + inode->i_ino - 1);

    if (inode_info->datah)
        mark_buffer_dirty(inode_info->datah);

    mark_buffer_dirty(msbi->sbh);
    mark_buffer_dirty(msbi->mdh);

    if (wbc->sync_mode == WB_SYNC_ALL) {
        MOD_INFO("SYNC ALL");
        if (inode_info->datah) {
            sync_dirty_buffer(inode_info->datah);
        }

        sync_dirty_buffer(msbi->sbh);
        sync_dirty_buffer(msbi->mdh);
    }

    // ERROR HADLING!

    return 0;
}

static struct inode *mfs_alloc_inode(struct super_block *sb)
{
    struct mfs_inode_info *inode_info =
            kmem_cache_zalloc(kmem_inode, GFP_KERNEL);
    MFS_SBI_INIT(msbi, sb);

    inode_info->max_files_in_dir = msbi->max_files_in_dir;
    inode_info->size = 0;

    inode_init_once(&inode_info->inode);
    return &inode_info->inode;
}

static void mfs_dtr_inode(struct inode *inode)
{
    MFS_INODE_INIT(ii, inode);

    if (ii->datah)
        brelse(ii->datah);

    kmem_cache_free(kmem_inode, ii);
}

static void mfs_put_super(struct super_block *sb)
{
    MFS_SBI_INIT(msbi, sb);

    if (!msbi)
        return;

    brelse(msbi->sbh);
    brelse(msbi->mdh);
    kfree(msbi);
}

static const struct super_operations mfs_so = {
    .statfs = simple_statfs,
    .drop_inode = generic_drop_inode,
    .put_super = mfs_put_super,
    .write_inode = mfs_write_inode,
    .alloc_inode = mfs_alloc_inode,
    .destroy_inode = mfs_dtr_inode,
};

static bool check_mfs_sb(struct mfs_sb *sb)
{
    u64 magic = le64_to_cpu(sb->magic);
    u8 ver = sb->version;

    if (magic != MFS_MAGIC) {
        MOD_ERR("Magic doesn't match: 0x%llx", magic);
        return false;
    }

    if (ver != 1) {
        MOD_ERR("Wrong version %u", ver);
        return false;
    }

    // Task 1: checksum with sha256

    return true;
}

static bool repair_mfs_md(struct mfs_sb_info *msbi)
{
    // Task 2: check that inodes on dev can exists with current configuration
    return true;
}

// ignore silent arg, it is not essential for this example
static int mfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct mfs_sb_info *msbi;
    struct inode *inode;
    int err = 0;

    msbi = kzalloc(sizeof(*msbi), GFP_KERNEL);
    if (!msbi) {
        err = -ENOMEM;
        MOD_ERR("Failed to allocate memory for super block");
        goto err;
    }

    sb_set_blocksize(sb, bdev_logical_block_size(sb->s_bdev));
    msbi->sbh = sb_bread(sb, to_blocks(MFS_SB_OFFSET_BYTES, sb));
    if (!msbi->sbh) {
        MOD_ERR("Failed to read data offset=%lu size=%lu", MFS_SB_OFFSET,
                MFS_SB_SIZE_BYTES);
        err = -EIO;
        goto err;
    }

    msbi->sb = (struct mfs_sb *)msbi->sbh->b_data;
    if (!check_mfs_sb(msbi->sb)) {
        err = -EINVAL;
        goto err;
    }

    msbi->mdh = sb_bread(sb, to_blocks(MFS_MD_OFFSET_BYTES, sb));
    if (!msbi->sbh) {
        MOD_ERR("Failed to read data offset=%lu size=%lu", MFS_SB_OFFSET,
                MFS_SB_SIZE_BYTES);
        err = -EIO;
        goto err;
    }

    msbi->md = (struct mfs_inode_disk *)msbi->mdh->b_data;
    if (!repair_mfs_md(msbi)) {
        err = -EINVAL;
        goto err;
    }

    // SB and MD are loaded, can start work
    msbi->data_offset = MFS_DATA_OFFSET_BYTES / sb->s_blocksize;
    msbi->max_files_in_dir = sb->s_blocksize / sizeof(struct mfs_dir_entry);
    msbi->max_inodes = min(sb->s_blocksize / sizeof(struct mfs_inode_disk),
                           MFS_MAX_INODES);
    sb->s_fs_info = msbi; // set private data

    sb->s_maxbytes = bdev_logical_block_size(sb->s_bdev);
    sb->s_magic = MFS_MAGIC;
    sb->s_op = &mfs_so;
    inode = mfs_iget(sb, 1);
    if (IS_ERR(inode)) {
        err = PTR_ERR(inode);
        MOD_ERR("Failed to get root inode, err=%d", err);
        goto err;
    }

    sb->s_root = d_make_root(inode);
    if (!sb->s_root) {
        err = -ENOMEM;
        MOD_ERR("Failed to create root");
        goto err;
    }

    MOD_INFO(
            "Mounted mfs on dev=%s, local_max_inodes=%u max_files_in_dir=%u, max_file=%llub",
            sb->s_bdev->bd_disk->disk_name, msbi->max_inodes,
            msbi->max_files_in_dir, sb->s_maxbytes);

    return 0;
err:
    if (msbi->sbh)
        brelse(msbi->sbh);
    if (msbi->mdh)
        brelse(msbi->mdh);
    if (msbi)
        kfree(msbi);
    return err;
}

// unmount
static void mfs_kill_sb(struct super_block *sb)
{
    // do other stuff
    kill_block_super(sb);
}

static struct dentry *mfs_mount(struct file_system_type *fs_type, int flags,
                                const char *dev_name, void *data)
{
    return mount_bdev(fs_type, flags, dev_name, data, mfs_fill_super);
}

static struct file_system_type mfs_fs_type = {
    .name = "mfs",
    .owner = THIS_MODULE,
    .mount = mfs_mount,
    .kill_sb = mfs_kill_sb,
    .fs_flags = FS_REQUIRES_DEV | FS_USERNS_MOUNT,
};

// ==================
// === mkfs sysfs ===
// ==================

static_assert(MFS_SB_SIZE_BYTES <= PAGE_SIZE);
static_assert(MFS_MD_SIZE_BYTES <= PAGE_SIZE);

struct __bio_waiter {
    struct completion cmpl;
    int err;
};

static void __bio_end(struct bio *bio)
{
    struct __bio_waiter *bio_end_data = bio->bi_private;

    bio_end_data->err = bio->bi_status;
    complete_all(&bio_end_data->cmpl);
}

static int __write_data(struct block_device *bdev, sector_t offset, ulong len,
                        struct page *page)
{
    int err = 0;
    struct bio *bio_write = NULL;
    struct __bio_waiter bio_end_data;

    bio_write = bio_alloc(bdev, 1, REQ_OP_WRITE, GFP_KERNEL);
    if (!bio_write) {
        MOD_ERR("Failed to alloc bio");
        err = -ENOMEM;
        goto failed;
    }

    bio_write->bi_iter.bi_sector = offset;
    if (!bio_add_page(bio_write, page, len, 0)) {
        MOD_ERR("Failed to add page to bio");
        err = -EIO;
        goto failed;
    }

    init_completion(&bio_end_data.cmpl);
    bio_write->bi_private = &bio_end_data;
    bio_write->bi_end_io = __bio_end;

    submit_bio(bio_write);
    wait_for_completion(&bio_end_data.cmpl);

    if (bio_end_data.err) {
        err = bio_end_data.err;
        MOD_ERR("Bio failed with err=%d offset=%llu len=%lu", err, offset, len);
    }

failed:
    if (bio_write)
        bio_put(bio_write);
    return err;
}

static ssize_t mkfs_store(struct kobject *kobj, struct kobj_attribute *attr,
                          const char *buf, size_t count)
{
    int err = 0;
    struct file *f = NULL;
    struct block_device *bdev = NULL;
    struct page *page = NULL;
    void *data = NULL;
    struct timespec64 now;
    ulong lb_size;

    f = bdev_file_open_by_path(buf, BLK_OPEN_WRITE, NULL, NULL);
    if (IS_ERR(f)) {
        err = PTR_ERR(f);
        f = NULL;
        MOD_ERR("Failed to open dev %s, err=%d", buf, err);
        goto failed;
    }

    bdev = file_bdev(f);
    lb_size = bdev_logical_block_size(bdev);
    page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!page) {
        MOD_ERR("Failed to alloc page");
        err = -ENOMEM;
        goto failed;
    }

    data = page_address(page);

    // write zeros to root inode data
    err = __write_data(bdev, MFS_DATA_OFFSET, PAGE_SIZE, page);

    *(struct mfs_sb *)data = (struct mfs_sb){
        .magic = cpu_to_le64(MFS_MAGIC),
        .version = 1,
    };
    __set_bit_le(0, &((struct mfs_sb *)data)->inode_map);

    err = __write_data(bdev, MFS_SB_OFFSET, MFS_SB_SIZE_BYTES, page);
    if (err)
        goto failed;

    ktime_get_coarse_real_ts64(&now);
    *(struct mfs_inode_disk *)data = (struct mfs_inode_disk){
        .i_gid = cpu_to_le16(0),
        .i_uid = cpu_to_le16(0),
        .i_nlinks = cpu_to_le16(2),
        .size = cpu_to_le16(2), // new root doesn't have files
        .time = cpu_to_le32(now.tv_sec),
        .i_mode = cpu_to_le16(S_IFDIR | S_IRUGO | S_IWUGO),
    };

    err = __write_data(bdev, MFS_MD_OFFSET, MFS_MD_SIZE_BYTES, page);
    if (err)
        goto failed;

    MOD_INFO("mkfs for %s is done", buf);
failed:
    if (page)
        free_page((ulong)data);
    if (f)
        fput(f);
    return err ? err : count;
}

static const struct kobj_attribute control_entry_attr = {
    .attr = {
        .name = "mkfs",
        .mode = S_IWUGO,
    },
    .store = mkfs_store,
};

// ===================
// === init module ===
// ===================

static int __init mfs_init(void)
{
    int err;

    kmem_inode = kmem_cache_create("mfs inode", sizeof(struct mfs_inode_info),
                                   NULL, 0);
    if (!kmem_inode) {
        MOD_ERR("Failed to create cache for kmem_inode");
        return -ENOMEM;
    }

    if ((err = sysfs_create_file(&THIS_MODULE->mkobj.kobj,
                                 &control_entry_attr.attr))) {
        MOD_ERR("Can't create file in sysfs, err %d", err);
        goto err;
    }

    if ((err = register_filesystem(&mfs_fs_type))) {
        MOD_ERR("Failed to register fs type, err=%d", err);
        goto err;
    }

    MOD_INFO(
            "Module loaded, sb_off=%lub md_off=%lub data_off=%lub max_files=%u max_name=%u",
            MFS_SB_OFFSET_BYTES, MFS_MD_OFFSET_BYTES, MFS_DATA_OFFSET_BYTES,
            MFS_MAX_INODES, MFS_MAX_FILENAME);
    return 0;
err:
    if (kmem_inode)
        kmem_cache_destroy(kmem_inode);
    sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &control_entry_attr.attr);
    return err;
}

static void __exit mfs_exit(void)
{
    rcu_barrier();
    unregister_filesystem(&mfs_fs_type);
    sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &control_entry_attr.attr);
    kmem_cache_destroy(kmem_inode);
    MOD_INFO("Module unloaded");
}

module_init(mfs_init);
module_exit(mfs_exit);
MODULE_LICENSE("GPL");
