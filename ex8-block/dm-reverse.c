#include "linux/bio.h"
#include "linux/blk_types.h"
#include "linux/blkdev.h"
#include "linux/compiler_attributes.h"
#include "linux/device-mapper.h"
#include "linux/gfp_types.h"
#include "linux/init.h"
#include "linux/mm.h"
#include <linux/module.h>

// Macros for logging
#define DM_MSG_PREFIX "reverse"

struct dmr {
    struct dm_dev *dev;
    sector_t size;
    uint lb_size;
};

struct dmr_read {
    uint bi_size;
};

// dmsetup create myname --table "0 65536 reverse /dev/vdb"
static int dmr_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    int err = 0;
    struct dmr *dmr = NULL;
    blk_mode_t mode = BLK_OPEN_READ | BLK_OPEN_WRITE;

    if (!argc) {
        err = -EINVAL;
        goto err;
    }

    dmr = kzalloc(sizeof(*dmr), GFP_KERNEL);
    if (!dmr) {
        err = -ENOMEM;
        goto err;
    }

    // mode = dm_table_get_mode(ti->table);
    err = dm_get_device(ti, argv[0], mode, &dmr->dev);
    if (err) {
        DMERR("Failed to get device %s", argv[0]);
        goto err;
    }

    ti->private = dmr;
    ti->accounts_remapped_io = true;
    ti->per_io_data_size = sizeof(struct dmr_read);
    dmr->size = bdev_nr_sectors(dmr->dev->bdev);
    dmr->lb_size = bdev_logical_block_size(dmr->dev->bdev);

    return 0;
err:
    if (dmr)
        kfree(dmr);
    return err;
}

static void dmr_dtr(struct dm_target *ti)
{
    struct dmr *dmr = ti->private;
    dm_put_device(ti, dmr->dev);
    kfree(dmr);
}

__maybe_unused static void __reverse_buf(struct page *page, size_t offset,
                                         size_t len)
{
    u8 *data = page_address(page) + offset;
    for (size_t i = 0; i < len; i++)
        data[i] = ~data[i];
}

static int dmr_map(struct dm_target *ti, struct bio *bio)
{
    struct dmr *dmr = ti->private;
    struct dmr_read *dmr_read = dm_per_bio_data(bio, sizeof(*dmr_read));
    struct bvec_iter iter;
    struct bio_vec bv;

    DMINFO("bio offset before=%llu", bio->bi_iter.bi_sector);
    DMINFO("bdev before: %s", bio->bi_bdev->bd_disk->disk_name);

    if (bio_op(bio) == REQ_OP_WRITE) {
        bio_for_each_segment(bv, bio, iter) {
            __reverse_buf(bv.bv_page, bv.bv_offset, bv.bv_len);
        }
    } else {
        dmr_read->bi_size = bio->bi_iter.bi_size;
    }

    bio->bi_iter.bi_sector = dmr->size - bio->bi_iter.bi_sector - 1 -
                             (bio->bi_iter.bi_size / dmr->lb_size);
    bio_set_dev(bio, dmr->dev->bdev);

    DMINFO("bio offset after=%llu", bio->bi_iter.bi_sector);
    DMINFO("bdev after: %s", bio->bi_bdev->bd_disk->disk_name);

    return DM_MAPIO_REMAPPED;
}

static int dmr_endio(struct dm_target *ti, struct bio *bio, blk_status_t *error)
{
    struct dmr_read *dmr_read = dm_per_bio_data(bio, sizeof(*dmr_read));
    struct bvec_iter iter;
    struct bio_vec bv;

    if (*error || bio_op(bio) != REQ_OP_READ)
        return 0;

    DMINFO("Reversing data for bio=%p", bio);

    bio->bi_iter.bi_size = dmr_read->bi_size;
    bio_for_each_segment(bv, bio, iter) {
        DMDEBUG("Buffrer %p offset %u len %u", bv.bv_page, bv.bv_offset,
                bv.bv_len);
        __reverse_buf(bv.bv_page, bv.bv_offset, bv.bv_len);
    }
    bio->bi_iter.bi_size = 0;

    return 0;
}

static struct target_type dmr_target = {
    .name = "reverse",
    .version = { 0, 0, 1 },
    .module = THIS_MODULE,
    .ctr = dmr_ctr,
    .dtr = dmr_dtr,
    .map = dmr_map,
    .end_io = dmr_endio,
};

static int __init dmr_init(void)
{
    int err = dm_register_target(&dmr_target);
    if (!err)
        DMINFO("Module loaded");
    return err;
}

static void __exit dmr_exit(void)
{
    dm_unregister_target(&dmr_target);
    DMINFO("Module unloaded");
}

module_init(dmr_init);
module_exit(dmr_exit);
MODULE_LICENSE("GPL");
