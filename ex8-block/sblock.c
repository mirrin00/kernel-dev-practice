#include "linux/bio.h"
#include "linux/blk-integrity.h"
#include "linux/blk_types.h"
#include "linux/blkdev.h"
#include "linux/byteorder/generic.h"
#include "linux/cleanup.h"
#include "linux/completion.h"
#include "linux/container_of.h"
#include "linux/crc-t10dif.h"
#include "linux/gfp.h"
#include "linux/gfp_types.h"
#include "linux/init.h"
#include "linux/list.h"
#include "linux/mm.h"
#include "linux/mutex.h"
#include "linux/numa.h"
#include "linux/scatterlist.h"
#include "linux/slab.h"
#include "linux/sysfs.h"
#include "linux/t10-pi.h"
#include "linux/types.h"
#include "linux/uio.h"
#include <linux/module.h>

// Macros for logging
#define MOD_PRFX "sblock: "
#define MOD_DEBUG(fmt, ...) pr_debug(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_INFO(fmt, ...) pr_info(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_WARN(fmt, ...) pr_warn(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_ERR(fmt, ...) pr_err(MOD_PRFX fmt "\n", ##__VA_ARGS__)

// ======================
// ==== Helper funcs ====
// ======================

static void __fill_pattern(char *page, ulong lbsize,
                           const char pattern[static 9])
{
    const ulong size = lbsize / 8;
    for (ulong i = 0; i < size; i++) {
        page[i * 8] = pattern[0];
        page[i * 8 + 1] = pattern[1];
        page[i * 8 + 2] = pattern[2];
        page[i * 8 + 3] = pattern[3];
        page[i * 8 + 4] = pattern[4];
        page[i * 8 + 5] = pattern[5];
        page[i * 8 + 6] = pattern[6];
        page[i * 8 + 7] = pattern[7];
    }
}

static char __opf_to_char(enum req_op opf)
{
    switch (opf) {
    case REQ_OP_READ:
        return 'r';
    case REQ_OP_WRITE:
        return 'w';
    default:
        return '?';
    }
}

static void __show_bio_info(const struct bio *bio)
{
    MOD_INFO("== Bio information ==");
    MOD_INFO("  bio addr: %p", bio);
    MOD_INFO("  bio flags: 0x%x", bio->bi_flags);
    MOD_INFO("  op flags: 0x%x (type=%c)", bio->bi_opf,
             __opf_to_char(bio_op(bio)));
    MOD_INFO("  start sector: 0x%llx", bio->bi_iter.bi_sector);
    MOD_INFO("  bio size (in bytes): 0x%x", bio->bi_iter.bi_size);
    MOD_INFO("  blockdev: %s", bio->bi_bdev->bd_disk->disk_name);
    MOD_INFO("  private data: %p", bio->bi_private);
    MOD_INFO("  end_io: %ps", bio->bi_end_io);
    MOD_INFO("  bvec count: %hu/%hu (actual/max)", bio->bi_vcnt,
             bio->bi_max_vecs);
    MOD_INFO("  bvec array: %p/%p (actual/inline)", bio->bi_io_vec,
             bio->bi_inline_vecs);
}

// ========================
// ==== Info about dev ====
// ========================

static int do_show_dev_info(char *args)
{
    int err = 0;
    char dev_name[48];
    struct file *f = NULL;
    struct block_device *bdev = NULL;
    struct blk_integrity *intg = NULL;

    err = sscanf(args, "%47s", dev_name);
    if (err == 1) {
        err = 0;
        MOD_INFO("dev info, arguments dev=%s", dev_name);
    } else {
        return -EINVAL;
    }

    f = bdev_file_open_by_path(dev_name, BLK_OPEN_READ, NULL, NULL);
    if (IS_ERR(f)) {
        err = PTR_ERR(f);
        f = NULL;
        MOD_ERR("Failed to open dev, err=%d", err);
        goto err;
    }
    bdev = file_bdev(f);

    MOD_INFO("== Block device info ==");
    MOD_INFO("  bdev: %p", bdev);
    MOD_INFO("  name: %s", bdev->bd_disk->disk_name);
    MOD_INFO("  major/minor: %hu:%hu", MAJOR(bdev->bd_dev),
             MINOR(bdev->bd_dev));
    MOD_INFO("  holder: %p", bdev->bd_holder);
    MOD_INFO("  start sector: 0x%llx", bdev->bd_start_sect);
    MOD_INFO("  sector count: 0x%llx", bdev->bd_nr_sectors);
    MOD_INFO("  sector size: %u", bdev_logical_block_size(bdev));
    MOD_INFO("  max discard sectors: %u", bdev_max_discard_sectors(bdev));
    MOD_INFO("  partno/is_part: %u/%u", bdev_partno(bdev),
             bdev_is_partition(bdev));
    MOD_INFO("  read-only: %u", bdev_read_only(bdev));
    MOD_INFO("  rotational: %u", !bdev_nonrot(bdev));
    intg = bdev_get_integrity(bdev);
    MOD_INFO("  integrity: %s",
             intg ? blk_integrity_profile_name(intg) : "nop");

err:
    if (f)
        fput(f);
    return err;
}

// ============================
// ==== Read/Write example ====
// ============================

#define READ_DATA_SIZE (32)
static char *read_data;

struct bio_waiter {
    struct completion cmpl;
    int err;
};

static void __bio_end(struct bio *bio)
{
    struct bio_waiter *bio_end_data = bio->bi_private;

    MOD_INFO("Bio end_io, bio=%p", bio);
    bio_end_data->err = bio->bi_status;
    complete_all(&bio_end_data->cmpl);
    bio_put(bio);
}

static int do_bio(const char *dev_name, sector_t start_sec, bool write,
                  const char pattern[static 9])
{
    int err = 0;
    struct file *f = NULL;
    struct block_device *bdev = NULL;
    struct bio *bio_write = NULL;
    uint lbsize;
    struct page *page = NULL;
    char *data_addr;
    struct bio_waiter bio_end_data;
    struct blk_integrity *intg = NULL;
    struct page *intg_page = NULL;

    f = bdev_file_open_by_path(dev_name, write ? BLK_OPEN_WRITE : BLK_OPEN_READ,
                               NULL, NULL);
    if (IS_ERR(f)) {
        err = PTR_ERR(f);
        f = NULL;
        MOD_ERR("Failed to open dev, err=%d", err);
        goto err;
    }
    bdev = file_bdev(f);
    lbsize = bdev_logical_block_size(bdev);
    MOD_INFO("Block size: %u", lbsize);

    bio_write =
            bio_alloc(bdev, 1, write ? REQ_OP_WRITE : REQ_OP_READ, GFP_KERNEL);

    bio_write->bi_iter.bi_sector = start_sec;

    page = alloc_page(GFP_KERNEL);
    if (!page) {
        MOD_ERR("Failed to alloc page");
        goto err;
    }

    data_addr = page_address(page);

    if (!bio_add_page(bio_write, page, lbsize, 0)) {
        MOD_ERR("Failed to add page to bio");
        goto err;
    }

    if (write)
        __fill_pattern(data_addr, lbsize, pattern);

    if ((intg = bdev_get_integrity(bdev))) {
        bio_integrity_alloc(bio_write, GFP_KERNEL, 1);
        intg_page = alloc_page(GFP_KERNEL);
        if (write) {
            struct t10_pi_tuple t10 = {
                // do not forget to convert values to be
                .guard_tag = cpu_to_be16(crc_t10dif(data_addr, lbsize)),
                .ref_tag = cpu_to_be32(0xCAFE),
                .app_tag = cpu_to_be16(0xDEAD),
            };

            memcpy(page_address(intg_page), &t10, sizeof(t10));
        }

        bio_integrity_add_page(bio_write, intg_page,
                               sizeof(struct t10_pi_tuple), 0);
    }

    // Setup end_request
    init_completion(&bio_end_data.cmpl);
    bio_write->bi_private = &bio_end_data;
    bio_write->bi_end_io = __bio_end;

    __show_bio_info(bio_write);
    submit_bio(bio_write);
    wait_for_completion(&bio_end_data.cmpl);

    if (bio_end_data.err) {
        MOD_ERR("Bio failed with err=%d", bio_end_data.err);
    } else {
        MOD_INFO("Bio is done");
    }

    if (!write && !bio_end_data.err)
        memcpy(read_data, data_addr, min(READ_DATA_SIZE, lbsize));

    if (!write && intg) {
        struct t10_pi_tuple t10;
        memcpy(&t10, page_address(intg_page), sizeof(t10));
        MOD_INFO("Integrity data: crc=%hx app=%hx ref=%hx", be16_to_cpu(t10.guard_tag),
                 be16_to_cpu(t10.app_tag), be32_to_cpu(t10.ref_tag));
    }

err:
    if (intg_page)
        free_page((ulong)page_address(intg_page));
    if (page)
        free_page((ulong)data_addr);
    if (f)
        fput(f);
    return err;
}

static int do_write(char *args)
{
    int err = 0;
    char dev_name[48];
    sector_t sec = 0;
    char pattern[9] = { 0 };

    err = sscanf(args, "%47s %lld %8s", dev_name, &sec, pattern);
    if (err == 3) {
        err = 0;
        MOD_INFO("write, arguments dev=%s sector=%lld pattern=%s", dev_name,
                 sec, pattern);
    } else {
        return -EINVAL;
    }

    return do_bio(dev_name, sec, true, pattern);
}

static int do_read(char *args)
{
    int err = 0;
    char dev_name[48];
    sector_t sec = 0;
    char pattern[9] = { 0 };

    err = sscanf(args, "%47s %lld", dev_name, &sec);
    if (err == 2) {
        err = 0;
        MOD_INFO("read, arguments dev=%s sector=%lld", dev_name, sec);
    } else {
        return -EINVAL;
    }

    return do_bio(dev_name, sec, false, pattern);
}

// =====================
// ==== Multi write ====
// =====================

struct bio_set *sb_bset;

static LIST_HEAD(multi_list);
static DEFINE_MUTEX(multi_lock);

struct multi_data {
    struct page *page;
    size_t pg_count;
    uint order;
    struct list_head list;
    struct kref kref;
};

static int do_multi_add(char *args)
{
    int err = 0;
    size_t pg_count;
    uint order = 0;
    char pattern[9] = { 0 };
    struct multi_data *d = NULL;

    err = sscanf(args, "%lu %8s", &pg_count, pattern);
    if (err == 2) {
        err = 0;
        MOD_INFO("chain add, arguments pg_count=%lu pattern=%s", pg_count,
                 pattern);
    } else {
        return -EINVAL;
    }

    d = kmalloc(sizeof(*d), GFP_KERNEL);
    if (!d) {
        err = -ENOMEM;
        goto err;
    }

    while (1 << order < pg_count)
        order++;
    d->order = order;

    MOD_INFO("Order is %u", order);

    d->page = alloc_pages(GFP_KERNEL, order);
    if (!d->page) {
        err = -ENOMEM;
        goto err;
    }

    __fill_pattern(page_address(d->page), pg_count * PAGE_SIZE, pattern);

    d->pg_count = pg_count;
    INIT_LIST_HEAD(&d->list);
    kref_init(&d->kref);
    scoped_guard(mutex, &multi_lock) {
        list_add_tail(&d->list, &multi_list);
    }

err:
    return err;
}

static void __clear_multi_data(struct kref *kref)
{
    struct multi_data *d = container_of(kref, typeof(*d), kref);

    free_pages((ulong)page_address(d->page), d->order);
    kfree(d);
}

static int do_multi_clear(char *args)
{
    int err = 0;
    LIST_HEAD(tmp_list);
    struct multi_data *d, *tmp;

    scoped_guard(mutex, &multi_lock) {
        list_splice_init(&multi_list, &tmp_list);
    }

    list_for_each_entry_safe(d, tmp, &tmp_list, list) {
        list_del(&d->list);
        kref_put(&d->kref, __clear_multi_data);
    }

    return err;
}

static int do_multi_write(char *args)
{
    int err = 0;
    char dev_name[48];
    struct file *f = NULL;
    struct block_device *bdev = NULL;
    struct bio *bio = NULL;
    sector_t offset;
    struct multi_data *d;
    struct bio_waiter bio_end_data;
    struct multi_data **arr = NULL;
    uint list_size = 0;

    err = sscanf(args, "%47s %llu", dev_name, &offset);
    if (err == 2) {
        err = 0;
        MOD_INFO("chain bio, arguments dev=%s offset=%llu", dev_name, offset);
    } else {
        return -EINVAL;
    }

    f = bdev_file_open_by_path(dev_name, BLK_OPEN_WRITE, NULL, NULL);
    if (IS_ERR(f)) {
        err = PTR_ERR(f);
        f = NULL;
        MOD_ERR("Failed to open dev, err=%d", err);
        goto err;
    }
    bdev = file_bdev(f);

    scoped_guard(mutex, &multi_lock) {
        uint cur_idx = 0;
        list_size = list_count_nodes(&multi_list);

        if (!list_size) {
            MOD_WARN("List is empty, nothing to do");
            goto err;
        }

        arr = kmalloc_array(list_size, sizeof(*arr), GFP_KERNEL);
        if (!arr) {
            MOD_ERR("Failed to allocate memory for array");
            err = -ENOMEM;
            goto err;
        }

        bio = bio_alloc_bioset(bdev, list_size, REQ_OP_WRITE, GFP_ATOMIC,
                               sb_bset);
        bio->bi_iter.bi_sector = offset;
        list_for_each_entry(d, &multi_list, list) {
            kref_get(&d->kref);
            arr[cur_idx++] = d;

            uint pg_size = d->pg_count * PAGE_SIZE;
            if (bio_add_page(bio, d->page, pg_size, 0) != pg_size) {
                MOD_WARN("Failed to add page with size %u", pg_size);
            }
        }
    }

    bio->bi_private = &bio_end_data;
    bio->bi_end_io = __bio_end;
    init_completion(&bio_end_data.cmpl);

    MOD_INFO("Submitting multi data");
    __show_bio_info(bio);
    submit_bio(bio);
    wait_for_completion(&bio_end_data.cmpl);
    if (bio_end_data.err)
        MOD_ERR("Multi bio failed with err=%d", bio_end_data.err);
    else
        MOD_INFO("Multi bio is done");

    for (uint cur_idx = 0; cur_idx < list_size; cur_idx++)
        kref_put(&arr[cur_idx]->kref, __clear_multi_data);

err:
    if (arr)
        kfree(arr);
    if (f)
        fput(f);
    return err;
}

// =====================
// ==== Chain bio ======
// =====================

static LIST_HEAD(chain_list);
static DEFINE_MUTEX(chain_lock);

struct chain_data {
    struct page *page;
    sector_t offset;
    bool is_write;
    struct list_head list;
    struct kref kref;
};

#define CHAIN_READ (0)
#define CHAIN_WRITE (1)

static int do_chain_add(char *args)
{
    int err = 0;
    sector_t offset;
    int type;
    char pattern[9] = { 0 };
    struct chain_data *d = NULL;

    err = sscanf(args, "%d %lld %8s", &type, &offset, pattern);
    if (err == 3) {
        err = 0;
        MOD_INFO("chain add, arguments type=%d sector=%lld pattern=%s", type,
                 offset, pattern);
    } else {
        return -EINVAL;
    }

    d = kmalloc(sizeof(*d), GFP_KERNEL);
    if (!d) {
        err = -ENOMEM;
        goto err;
    }

    d->page = alloc_page(GFP_KERNEL);
    if (!d->page) {
        err = -ENOMEM;
        goto err;
    }

    if (type == CHAIN_WRITE) {
        d->is_write = true;
        __fill_pattern(page_address(d->page), PAGE_SIZE, pattern);
    } else {
        d->is_write = false;
    }

    d->offset = offset;
    INIT_LIST_HEAD(&d->list);
    kref_init(&d->kref);
    scoped_guard(mutex, &chain_lock) {
        list_add_tail(&d->list, &chain_list);
    }

err:
    return err;
}

static void __clear_chain_data(struct kref *kref)
{
    struct chain_data *d = container_of(kref, typeof(*d), kref);

    free_page((ulong)page_address(d->page));
    kfree(d);
}

static int do_chain_clear(char *args)
{
    int err = 0;
    LIST_HEAD(tmp_list);
    struct chain_data *d, *tmp;

    scoped_guard(mutex, &chain_lock) {
        list_splice_init(&chain_list, &tmp_list);
    }

    list_for_each_entry_safe(d, tmp, &tmp_list, list) {
        list_del(&d->list);
        kref_put(&d->kref, __clear_chain_data);
    }

    return err;
}

static int do_chain_bio(char *args)
{
    int err = 0;
    char dev_name[48];
    struct file *f = NULL;
    struct block_device *bdev = NULL;
    struct bio *head_bio = NULL;
    struct chain_data *d;
    struct bio_waiter bio_end_data;
    struct chain_data **arr = NULL;
    uint list_size = 0;

    err = sscanf(args, "%47s", dev_name);
    if (err == 1) {
        err = 0;
        MOD_INFO("chain bio, arguments dev=%s", dev_name);
    } else {
        return -EINVAL;
    }

    f = bdev_file_open_by_path(dev_name, BLK_OPEN_WRITE | BLK_OPEN_READ, NULL,
                               NULL);
    if (IS_ERR(f)) {
        err = PTR_ERR(f);
        f = NULL;
        MOD_ERR("Failed to open dev, err=%d", err);
        goto err;
    }
    bdev = file_bdev(f);

    scoped_guard(mutex, &chain_lock) {
        uint cur_idx = 0;
        list_size = list_count_nodes(&chain_list);

        if (!list_size) {
            MOD_WARN("List is empty, nothing to do");
            goto err;
        }

        arr = kmalloc_array(list_size, sizeof(*arr), GFP_KERNEL);
        if (!arr) {
            MOD_ERR("Failed to allocate memory for array");
            err = -ENOMEM;
            goto err;
        }

        list_for_each_entry(d, &chain_list, list) {
            kref_get(&d->kref);
            arr[cur_idx++] = d;

            struct bio *bio = bio_alloc_bioset(
                    bdev, 1, d->is_write ? REQ_OP_WRITE : REQ_OP_READ,
                    GFP_ATOMIC, sb_bset);
            bio->bi_iter.bi_sector = d->offset;
            if (bio_add_page(bio, d->page, PAGE_SIZE, 0) != PAGE_SIZE) {
                MOD_WARN("Failed to add page for offset %lld (is_write=%d)",
                         d->offset, d->is_write);
            }
            if (head_bio) {
                bio_chain(head_bio, bio);
                submit_bio(head_bio);
            }
            head_bio = bio;
        }
    }

    head_bio->bi_private = &bio_end_data;
    head_bio->bi_end_io = __bio_end;
    init_completion(&bio_end_data.cmpl);

    MOD_INFO("Submitting chain data");
    __show_bio_info(head_bio);
    submit_bio(head_bio);
    wait_for_completion(&bio_end_data.cmpl);
    if (bio_end_data.err)
        MOD_ERR("Chain bio failed with err=%d", bio_end_data.err);
    else
        MOD_INFO("Chain bio is done");

    for (uint cur_idx = 0; cur_idx < list_size; cur_idx++)
        kref_put(&arr[cur_idx]->kref, __clear_chain_data);

err:
    if (arr)
        kfree(arr);
    if (f)
        fput(f);
    return err;
}

static int do_chain_print_read(char *args)
{
    int err = 0;
    struct chain_data *d;
    char *data;
    char str[32 + 4];
    uint str_idx;

    memset(str, ' ', sizeof(str));
    str[35] = '\0';

    scoped_guard(mutex, &chain_lock) {
        list_for_each_entry(d, &chain_list, list) {
            if (d->is_write)
                continue;

            data = page_address(d->page);
            str_idx = 34;
            for (int i = 31; i >= 0; i--) {
                str[str_idx--] = data[i];
                if (i % 8 == 0)
                    str_idx--;
            }
            MOD_INFO("Read data at %lld: %s", d->offset, str);
        }
    }

    return err;
}

// ======================
// ==== Create blk ======
// ======================

struct sblock {
    struct gendisk *disk;
    struct block_device *bdev;
    struct request_queue *queue;
    atomic_t opens;
    struct list_head list;
};

static int sblock_open(struct gendisk *disk, blk_mode_t mode)
{
    struct sblock *blk = disk->private_data;

    if (!atomic_inc_not_zero(&blk->opens)) {
        MOD_ERR("Device %s is under closing", disk->disk_name);
        return -EINVAL;
    }

    MOD_INFO("Device %s is opened, counter=%d", disk->disk_name,
             atomic_read(&blk->opens));
    return 0;
}

static void sblock_release(struct gendisk *disk)
{
    struct sblock *blk = disk->private_data;

    atomic_dec(&blk->opens);
    MOD_INFO("Device %s is closed, counter=%d", disk->disk_name,
             atomic_read(&blk->opens));
}

#define PRT_NUM (8)

__maybe_unused static void sblock_process_sgt(struct sg_table *sgt)
{
    struct scatterlist *sg;
    uint i;
    char prt[PRT_NUM + 1] = { 0 };

    for_each_sgtable_sg(sgt, sg, i) {
        memcpy(prt, page_address(sg_page(sg)), PRT_NUM);
        MOD_INFO("blk: [%d] process_sgt page pattern=%s", i, prt);
    }

    sg_free_table(sgt);
}

static void sblock_submit_bio(struct bio *bio)
{
    struct bvec_iter b_iter;
    struct bio_vec bv;

    uint nents = bio->bi_vcnt;
    int err;
    struct scatterlist *sg;
    struct sg_table sgt;

    err = sg_alloc_table(&sgt, nents, GFP_KERNEL);

    if (err) {
        bio->bi_status = BLK_STS_IOERR;
        bio_endio(bio);
        return;
    }

    sg = sgt.sgl;

    bio_for_each_bvec(bv, bio, b_iter) {
        sg_set_page(sg, bv.bv_page, bv.bv_len, bv.bv_offset);
        sg = sg_next(sg);
    }

    sblock_process_sgt(&sgt);

    __show_bio_info(bio);
    bio->bi_status = 0;
    bio_endio(bio);
}

static struct block_device_operations sblk_ops = {
    .owner = THIS_MODULE,
    .open = sblock_open,
    .release = sblock_release,
    .submit_bio = sblock_submit_bio,
};

static DEFINE_MUTEX(sblock_lock);
static LIST_HEAD(sblock_list);

#define SBLOCK_MAJOR (216)
#define SBLOCK_CAP (24 * 1024 * 2)
#define SBLOCK_LBA (2048)

static void __init_qlims(struct queue_limits *ql)
{
    ql->physical_block_size = SBLOCK_LBA;
    ql->logical_block_size = SBLOCK_LBA;
    ql->io_min = SECTOR_SIZE;
    ql->max_segments = BIO_MAX_VECS;
    ql->max_hw_sectors = (PAGE_SIZE / SECTOR_SIZE) * ql->max_segments;
    ql->features |= BLK_FEAT_ROTATIONAL;
}

static int do_create_blk(char *args)
{
    int err = 0;
    char dev_name[DISK_NAME_LEN] = { 0 };
    struct sblock *blk = NULL;
    struct gendisk *disk = NULL;
    struct queue_limits qlims = { 0 };

    err = sscanf(args, "%31s", dev_name);
    if (err == 1) {
        err = 0;
        MOD_INFO("create blk, arguments dev=%s", dev_name);
    } else {
        return -EINVAL;
    }

    blk = kmalloc(sizeof(*blk), GFP_KERNEL);
    if (!blk) {
        err = -ENOMEM;
        MOD_ERR("Failed to alloc memory for blk");
        goto err;
    }

    __init_qlims(&qlims);
    blk->disk = disk = blk_alloc_disk(&qlims, NUMA_NO_NODE);
    if (IS_ERR(disk)) {
        err = PTR_ERR(disk);
        MOD_ERR("Failed to alloc disk, err=%d", err);
        goto err;
    }

    blk->queue = disk->queue;
    blk->queue->queuedata = blk;
    disk->fops = &sblk_ops;

    blk_queue_flag_set(QUEUE_FLAG_STATS, blk->queue);

    disk->major = 0;
    disk->first_minor = 0;
    disk->minors = 0;
    disk->flags |= GENHD_FL_NO_PART; // no parts ^)
    disk->private_data = blk;

    set_capacity(disk, SBLOCK_CAP);
    memcpy(disk->disk_name, dev_name, DISK_NAME_LEN);
    atomic_set(&blk->opens, 1);

    err = add_disk(blk->disk);
    if (err) {
        MOD_ERR("Failed to add disk, err=%d", err);
        del_gendisk(blk->disk);
        goto err;
    }

    blk->bdev = disk->part0;
    INIT_LIST_HEAD(&blk->list);

    scoped_guard(mutex, &sblock_lock) {
        list_add(&blk->list, &sblock_list);
    }

    MOD_INFO("Device %s is created", disk->disk_name);

    return 0;
err:
    if (blk)
        kfree(blk);
    return err;
}

static int do_remove_blk(char *args)
{
    int err = 0;
    char dev_name[DISK_NAME_LEN] = { 0 };
    struct sblock *blk = NULL;

    err = sscanf(args, "%31s", dev_name);
    if (err == 1) {
        err = 0;
        MOD_INFO("create blk, arguments dev=%s", dev_name);
    } else {
        return -EINVAL;
    }

    scoped_guard(mutex, &sblock_lock) {
        struct sblock *cur, *tmp;
        list_for_each_entry_safe(cur, tmp, &sblock_list, list) {
            if (!strncmp(dev_name, cur->disk->disk_name, 32)) {
                if (atomic_cmpxchg(&cur->opens, 1, 0) == 1) {
                    // zero, safely can close
                    list_del(&cur->list);
                    blk = cur;
                    break;
                } else {
                    MOD_ERR("Device %s is hold by someone, cur=%d", dev_name,
                            atomic_read(&cur->opens));
                    return -EPERM;
                }
            }
        }
    }

    del_gendisk(blk->disk);
    put_disk(blk->disk);
    kfree(blk);

    MOD_INFO("Removed device %s", dev_name);
    return 0;
}

// =======================
// ======= SYSFS =========
// =======================

typedef int (*cmd_func_t)(char *args);

#define __STR_TO_command(name, f) { name, sizeof(name) - 1, f }
#define STR_TO_command(name, f) __STR_TO_command(name " ", f)

static struct {
    const char *name;
    size_t len;
    cmd_func_t func;
} str_to_op[] = {
    STR_TO_command("write", do_write),
    STR_TO_command("read", do_read),
    STR_TO_command("dev_info", do_show_dev_info),
    STR_TO_command("madd", do_multi_add),
    STR_TO_command("mclear", do_multi_clear),
    STR_TO_command("mwrite", do_multi_write),
    STR_TO_command("ch_add", do_chain_add),
    STR_TO_command("ch_clear", do_chain_clear),
    STR_TO_command("ch_bio", do_chain_bio),
    STR_TO_command("ch_print", do_chain_print_read),
    STR_TO_command("cblk", do_create_blk),
    STR_TO_command("rblk", do_remove_blk),
};

#define MAX_ENTRY_NAME (128)

static cmd_func_t parse_cmd(const char *buf, size_t count, char *str)
{
    cmd_func_t res = NULL;
    for (uint i = 0; i < ARRAY_SIZE(str_to_op); i++) {
        MOD_DEBUG("Comparing '%s' and '%s' (%ld)", str_to_op[i].name, buf,
                  str_to_op[i].len);
        if (!strncmp(str_to_op[i].name, buf, str_to_op[i].len - 1)) {
            res = str_to_op[i].func;
            buf += str_to_op[i].len;
            count -= str_to_op[i].len;
            break;
        }
    }

    if (res)
        strncpy(str, buf, MIN(count, MAX_ENTRY_NAME - 1));

    return res;
}

static ssize_t _sysfs_store(struct kobject *kobj, struct kobj_attribute *attr,
                            const char *buf, size_t count)
{
    int err = 0;
    char args[MAX_ENTRY_NAME];
    cmd_func_t func = parse_cmd(buf, count, args);

    if (func) {
        err = func(args);
    } else {
        MOD_WARN("Unkown command");
        err = -EINVAL;
    }

    return err ? err : count;
}

#define CHARS_PER_LINE (8)

static ssize_t _sysfs_show(struct kobject *kobj, struct kobj_attribute *attr,
                           char *buf)
{
    ssize_t ret = 0;
    ssize_t data_size = READ_DATA_SIZE;
    ssize_t iters = data_size / CHARS_PER_LINE;

    for (ssize_t i = 0; i < iters; i++) {
        memcpy(buf + ret, read_data, CHARS_PER_LINE);
        ret += CHARS_PER_LINE;
        ret += sysfs_emit_at(buf, ret, "\n");
    }

    return ret;
}

static const struct kobj_attribute control_entry_attr = {
    .attr = {
        .name = "control",
        .mode = S_IRUGO | S_IWUGO,
    },
    .show = _sysfs_show,
    .store = _sysfs_store,
};

static int __init block_init(void)
{
    int err = 0;

    if ((err = sysfs_create_file(&THIS_MODULE->mkobj.kobj,
                                 &control_entry_attr.attr))) {
        MOD_ERR("Can't create file in sysfs, err %d", err);
        return err;
    }

    read_data = kzalloc(READ_DATA_SIZE, GFP_KERNEL);
    if (!read_data) {
        MOD_ERR("Failed to alloc memory");
        err = -ENOMEM;
        goto err;
    }

    sb_bset = kzalloc(sizeof(*sb_bset), GFP_KERNEL);
    if (!sb_bset) {
        MOD_ERR("Failed to alloc memory for bioset");
        err = -ENOMEM;
        goto err;
    }

    err = bioset_init(sb_bset, 512, 0, BIOSET_NEED_BVECS);
    if (err) {
        MOD_ERR("Failed to init bioset, err=%d", err);
        goto err;
    }

    MOD_INFO("module loaded");

    return 0;

err:
    if (sb_bset)
        kfree(sb_bset);
    if (read_data)
        kfree(read_data);
    sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &control_entry_attr.attr);
    return err;
}

static void __exit block_exit(void)
{
    do_multi_clear("");
    do_chain_clear("");
    bioset_exit(sb_bset);
    kfree(sb_bset);
    kfree(read_data);
    sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &control_entry_attr.attr);
    MOD_INFO("module unloaded");
}

module_init(block_init);
module_exit(block_exit);
MODULE_LICENSE("GPL");
