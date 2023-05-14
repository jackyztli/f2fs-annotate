// SPDX-License-Identifier: GPL-2.0
/*
 * fs/f2fs/checkpoint.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/f2fs_fs.h>
#include <linux/pagevec.h>
#include <linux/swap.h>
#include <linux/kthread.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "iostat.h"
#include <trace/events/f2fs.h>

#define DEFAULT_CHECKPOINT_IOPRIO (IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 3))

static struct kmem_cache *ino_entry_slab;
struct kmem_cache *f2fs_inode_entry_slab;

// 设置CP错误标记
void f2fs_stop_checkpoint(struct f2fs_sb_info *sbi, bool end_io,
						unsigned char reason)
{
	f2fs_build_fault_attr(sbi, 0, 0);
	set_ckpt_flags(sbi, CP_ERROR_FLAG);
	if (!end_io) {
		f2fs_flush_merged_writes(sbi);

		// 覆盖SB区域？？？
		f2fs_handle_stop(sbi, reason);
	}
}

/*
 * We guarantee no failure on the returned page.
 */
// 从page cache获取一个元数据页，上层接口保证该页存在
struct page *f2fs_grab_meta_page(struct f2fs_sb_info *sbi, pgoff_t index)
{
	struct address_space *mapping = META_MAPPING(sbi);
	struct page *page;
repeat:
	page = f2fs_grab_cache_page(mapping, index, false);
	if (!page) {
		cond_resched();
		goto repeat;
	}
	f2fs_wait_on_page_writeback(page, META, true, true);
	if (!PageUptodate(page))
		SetPageUptodate(page);
	return page;
}

// 从page cache获取一个元数据页，如果该页不存在，则从设备中读取
static struct page *__get_meta_page(struct f2fs_sb_info *sbi, pgoff_t index,
							bool is_meta)
{
	struct address_space *mapping = META_MAPPING(sbi);
	struct page *page;
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.type = META,
		.op = REQ_OP_READ,
		.op_flags = REQ_META | REQ_PRIO,
		.old_blkaddr = index,
		.new_blkaddr = index,
		.encrypted_page = NULL,
		.is_por = !is_meta ? 1 : 0,
	};
	int err;

	if (unlikely(!is_meta))
		fio.op_flags &= ~REQ_META;
repeat:
	page = f2fs_grab_cache_page(mapping, index, false);
	if (!page) {
		cond_resched();
		goto repeat;
	}
	if (PageUptodate(page))
		goto out;

	fio.page = page;

	err = f2fs_submit_page_bio(&fio);
	if (err) {
		f2fs_put_page(page, 1);
		return ERR_PTR(err);
	}

	f2fs_update_iostat(sbi, NULL, FS_META_READ_IO, F2FS_BLKSIZE);

	lock_page(page);
	if (unlikely(page->mapping != mapping)) {
		f2fs_put_page(page, 1);
		goto repeat;
	}

	if (unlikely(!PageUptodate(page))) {
		f2fs_handle_page_eio(sbi, page->index, META);
		f2fs_put_page(page, 1);
		return ERR_PTR(-EIO);
	}
out:
	return page;
}

struct page *f2fs_get_meta_page(struct f2fs_sb_info *sbi, pgoff_t index)
{
	return __get_meta_page(sbi, index, true);
}

struct page *f2fs_get_meta_page_retry(struct f2fs_sb_info *sbi, pgoff_t index)
{
	struct page *page;
	int count = 0;

retry:
	page = __get_meta_page(sbi, index, true);
	if (IS_ERR(page)) {
		if (PTR_ERR(page) == -EIO &&
				++count <= DEFAULT_RETRY_IO_COUNT)
			goto retry;
		f2fs_stop_checkpoint(sbi, false, STOP_CP_REASON_META_PAGE);
	}
	return page;
}

/* for POR only */
struct page *f2fs_get_tmp_page(struct f2fs_sb_info *sbi, pgoff_t index)
{
	return __get_meta_page(sbi, index, false);
}

static bool __is_bitmap_valid(struct f2fs_sb_info *sbi, block_t blkaddr,
							int type)
{
	struct seg_entry *se;
	unsigned int segno, offset;
	bool exist;

	if (type == DATA_GENERIC)
		return true;

	segno = GET_SEGNO(sbi, blkaddr);
	offset = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);
	se = get_seg_entry(sbi, segno);

	exist = f2fs_test_bit(offset, se->cur_valid_map);
	if (exist && type == DATA_GENERIC_ENHANCE_UPDATE) {
		f2fs_err(sbi, "Inconsistent error blkaddr:%u, sit bitmap:%d",
			 blkaddr, exist);
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		return exist;
	}

	if (!exist && type == DATA_GENERIC_ENHANCE) {
		f2fs_err(sbi, "Inconsistent error blkaddr:%u, sit bitmap:%d",
			 blkaddr, exist);
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		dump_stack();
	}
	return exist;
}

// 判断blkaddr地址是否合法
bool f2fs_is_valid_blkaddr(struct f2fs_sb_info *sbi,
					block_t blkaddr, int type)
{
	if (time_to_inject(sbi, FAULT_BLKADDR))
		return false;

	switch (type) {
	case META_NAT:
		break;
	case META_SIT:
		if (unlikely(blkaddr >= SIT_BLK_CNT(sbi)))
			return false;
		break;
	case META_SSA:
		if (unlikely(blkaddr >= MAIN_BLKADDR(sbi) ||
			blkaddr < SM_I(sbi)->ssa_blkaddr))
			return false;
		break;
	case META_CP:
		if (unlikely(blkaddr >= SIT_I(sbi)->sit_base_addr ||
			blkaddr < __start_cp_addr(sbi)))
			return false;
		break;
	case META_POR:
		if (unlikely(blkaddr >= MAX_BLKADDR(sbi) ||
			blkaddr < MAIN_BLKADDR(sbi)))
			return false;
		break;
	case DATA_GENERIC:
	case DATA_GENERIC_ENHANCE:
	case DATA_GENERIC_ENHANCE_READ:
	case DATA_GENERIC_ENHANCE_UPDATE:
		if (unlikely(blkaddr >= MAX_BLKADDR(sbi) ||
				blkaddr < MAIN_BLKADDR(sbi))) {
			f2fs_warn(sbi, "access invalid blkaddr:%u",
				  blkaddr);
			set_sbi_flag(sbi, SBI_NEED_FSCK);
			dump_stack();
			return false;
		} else {
			return __is_bitmap_valid(sbi, blkaddr, type);
		}
		break;
	case META_GENERIC:
		if (unlikely(blkaddr < SEG0_BLKADDR(sbi) ||
			blkaddr >= MAIN_BLKADDR(sbi)))
			return false;
		break;
	default:
		BUG();
	}

	return true;
}

/*
 * Readahead CP/NAT/SIT/SSA/POR pages
 */
// 预读元数据区域的nrpages页
int f2fs_ra_meta_pages(struct f2fs_sb_info *sbi, block_t start, int nrpages,
							int type, bool sync)
{
	struct page *page;
	block_t blkno = start;
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.type = META,
		.op = REQ_OP_READ,
		.op_flags = sync ? (REQ_META | REQ_PRIO) : REQ_RAHEAD,
		.encrypted_page = NULL,
		.in_list = 0,
		.is_por = (type == META_POR) ? 1 : 0,
	};
	struct blk_plug plug;
	int err;

	if (unlikely(type == META_POR))
		fio.op_flags &= ~REQ_META;

	blk_start_plug(&plug);
	for (; nrpages-- > 0; blkno++) {

		if (!f2fs_is_valid_blkaddr(sbi, blkno, type))
			goto out;

		switch (type) {
		// 由于NAT/SIT有两个区域，所以需要判断读取的是哪个区域的数据
		case META_NAT:
			if (unlikely(blkno >=
					NAT_BLOCK_OFFSET(NM_I(sbi)->max_nid)))
				blkno = 0;
			/* get nat block addr */
			fio.new_blkaddr = current_nat_addr(sbi,
					blkno * NAT_ENTRY_PER_BLOCK);
			break;
		case META_SIT:
			if (unlikely(blkno >= TOTAL_SEGS(sbi)))
				goto out;
			/* get sit block addr */
			fio.new_blkaddr = current_sit_addr(sbi,
					blkno * SIT_ENTRY_PER_BLOCK);
			break;
		case META_SSA:
		case META_CP:
		case META_POR:
			fio.new_blkaddr = blkno;
			break;
		default:
			BUG();
		}

		page = f2fs_grab_cache_page(META_MAPPING(sbi),
						fio.new_blkaddr, false);
		if (!page)
			continue;
		if (PageUptodate(page)) {
			f2fs_put_page(page, 1);
			continue;
		}

		fio.page = page;
		err = f2fs_submit_page_bio(&fio);
		f2fs_put_page(page, err ? 1 : 0);

		if (!err)
			f2fs_update_iostat(sbi, NULL, FS_META_READ_IO,
							F2FS_BLKSIZE);
	}
out:
	blk_finish_plug(&plug);
	return blkno - start;
}

// 读取逻辑号为index的元数据页，并且预读ra_blocks个页
void f2fs_ra_meta_pages_cond(struct f2fs_sb_info *sbi, pgoff_t index,
							unsigned int ra_blocks)
{
	struct page *page;
	bool readahead = false;

	if (ra_blocks == RECOVERY_MIN_RA_BLOCKS)
		return;

	page = find_get_page(META_MAPPING(sbi), index);
	if (!page || !PageUptodate(page))
		readahead = true;
	f2fs_put_page(page, 0);

	if (readahead)
		f2fs_ra_meta_pages(sbi, index, ra_blocks, META_POR, true);
}

static int __f2fs_write_meta_page(struct page *page,
				struct writeback_control *wbc,
				enum iostat_type io_type)
{
	struct f2fs_sb_info *sbi = F2FS_P_SB(page);

	trace_f2fs_writepage(page, META);

	if (unlikely(f2fs_cp_error(sbi)))
		goto redirty_out;
	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto redirty_out;
	if (wbc->for_reclaim && page->index < GET_SUM_BLOCK(sbi, 0))
		goto redirty_out;

	f2fs_do_write_meta_page(sbi, page, io_type);
	dec_page_count(sbi, F2FS_DIRTY_META);

	if (wbc->for_reclaim)
		f2fs_submit_merged_write_cond(sbi, NULL, page, 0, META);

	unlock_page(page);

	if (unlikely(f2fs_cp_error(sbi)))
		f2fs_submit_merged_write(sbi, META);

	return 0;

redirty_out:
	redirty_page_for_writepage(wbc, page);
	return AOP_WRITEPAGE_ACTIVATE;
}

// 写入一个元数据页
static int f2fs_write_meta_page(struct page *page,
				struct writeback_control *wbc)
{
	return __f2fs_write_meta_page(page, wbc, FS_META_IO);
}

// 写入一个范围的元数据
static int f2fs_write_meta_pages(struct address_space *mapping,
				struct writeback_control *wbc)
{
	struct f2fs_sb_info *sbi = F2FS_M_SB(mapping);
	long diff, written;

	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto skip_write;

	/* collect a number of dirty meta pages and write together */
	if (wbc->sync_mode != WB_SYNC_ALL &&
			get_pages(sbi, F2FS_DIRTY_META) <
					nr_pages_to_skip(sbi, META))
		goto skip_write;

	/* if locked failed, cp will flush dirty pages instead */
	if (!f2fs_down_write_trylock(&sbi->cp_global_sem))
		goto skip_write;

	trace_f2fs_writepages(mapping->host, wbc, META);
	diff = nr_pages_to_write(sbi, META, wbc);
	// 同步写入
	written = f2fs_sync_meta_pages(sbi, META, wbc->nr_to_write, FS_META_IO);
	f2fs_up_write(&sbi->cp_global_sem);
	wbc->nr_to_write = max((long)0, wbc->nr_to_write - written - diff);
	return 0;

skip_write:
	wbc->pages_skipped += get_pages(sbi, F2FS_DIRTY_META);
	trace_f2fs_writepages(mapping->host, wbc, META);
	return 0;
}

// 将元数据页下刷（例如SIT/NAT区域等）
long f2fs_sync_meta_pages(struct f2fs_sb_info *sbi, enum page_type type,
				long nr_to_write, enum iostat_type io_type)
{
	struct address_space *mapping = META_MAPPING(sbi);
	pgoff_t index = 0, prev = ULONG_MAX;
	struct folio_batch fbatch;
	long nwritten = 0;
	int nr_folios;
	struct writeback_control wbc = {
		.for_reclaim = 0,
	};
	struct blk_plug plug;

	folio_batch_init(&fbatch);

	blk_start_plug(&plug);

	// 遍历元数据树中脏页
	while ((nr_folios = filemap_get_folios_tag(mapping, &index,
					(pgoff_t)-1,
					PAGECACHE_TAG_DIRTY, &fbatch))) {
		int i;

		for (i = 0; i < nr_folios; i++) {
			struct folio *folio = fbatch.folios[i];

			if (nr_to_write != LONG_MAX && i != 0 &&
					folio->index != prev +
					folio_nr_pages(fbatch.folios[i-1])) {
				folio_batch_release(&fbatch);
				goto stop;
			}

			folio_lock(folio);

			if (unlikely(folio->mapping != mapping)) {
continue_unlock:
				folio_unlock(folio);
				continue;
			}

			// 如果该元数据非脏（其他任务，可能是bdi已经下刷该页）
			if (!folio_test_dirty(folio)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			// 等待脏回写完成
			f2fs_wait_on_page_writeback(&folio->page, META,
					true, true);

			if (!folio_clear_dirty_for_io(folio))
				goto continue_unlock;

			// 将该脏元数据落盘
			if (__f2fs_write_meta_page(&folio->page, &wbc,
						io_type)) {
				folio_unlock(folio);
				break;
			}
			nwritten += folio_nr_pages(folio);
			prev = folio->index;
			if (unlikely(nwritten >= nr_to_write))
				break;
		}
		folio_batch_release(&fbatch);
		cond_resched();
	}
stop:
	if (nwritten)
		f2fs_submit_merged_write(sbi, type);

	blk_finish_plug(&plug);

	return nwritten;
}

// 将一个脏元数据置脏
static bool f2fs_dirty_meta_folio(struct address_space *mapping,
		struct folio *folio)
{
	trace_f2fs_set_page_dirty(&folio->page, META);

	// 如果该元数据非uptodata，则置上该标记
	if (!folio_test_uptodate(folio))
		folio_mark_uptodate(folio);
	// 对该元数据置脏，调整对应的统计数据
	if (filemap_dirty_folio(mapping, folio)) {
		inc_page_count(F2FS_M_SB(mapping), F2FS_DIRTY_META);
		set_page_private_reference(&folio->page);
		return true;
	}
	return false;
}

const struct address_space_operations f2fs_meta_aops = {
	.writepage	= f2fs_write_meta_page,
	.writepages	= f2fs_write_meta_pages,
	.dirty_folio	= f2fs_dirty_meta_folio,
	.invalidate_folio = f2fs_invalidate_folio,
	.release_folio	= f2fs_release_folio,
	.migrate_folio	= filemap_migrate_folio,
};

static void __add_ino_entry(struct f2fs_sb_info *sbi, nid_t ino,
						unsigned int devidx, int type)
{
	struct inode_management *im = &sbi->im[type];
	struct ino_entry *e = NULL, *new = NULL;

	// 如果是需要下刷的inode类型，则从ino_root中查找
	if (type == FLUSH_INO) {
		rcu_read_lock();
		e = radix_tree_lookup(&im->ino_root, ino);
		rcu_read_unlock();
	}

retry:
	// 如果该inode管理信息不存在，则分配一个
	if (!e)
		new = f2fs_kmem_cache_alloc(ino_entry_slab,
						GFP_NOFS, true, NULL);

	radix_tree_preload(GFP_NOFS | __GFP_NOFAIL);

	spin_lock(&im->ino_lock);
	e = radix_tree_lookup(&im->ino_root, ino);
	if (!e) {
		if (!new) {
			spin_unlock(&im->ino_lock);
			goto retry;
		}
		e = new;
		if (unlikely(radix_tree_insert(&im->ino_root, ino, e)))
			f2fs_bug_on(sbi, 1);

		// 重置inode管理数据
		memset(e, 0, sizeof(struct ino_entry));
		e->ino = ino;

		// 添加到inode管理cache中
		list_add_tail(&e->list, &im->ino_list);
		if (type != ORPHAN_INO)
			im->ino_num++;
	}

	// 如果该inode需要在fsync/CP等流程下刷，则置上对应的设备位（用于多设备场景）
	if (type == FLUSH_INO)
		f2fs_set_bit(devidx, (char *)&e->dirty_device);

	spin_unlock(&im->ino_lock);
	radix_tree_preload_end();

	if (new && e != new)
		kmem_cache_free(ino_entry_slab, new);
}

// 删除一个inode管理数据
static void __remove_ino_entry(struct f2fs_sb_info *sbi, nid_t ino, int type)
{
	struct inode_management *im = &sbi->im[type];
	struct ino_entry *e;

	spin_lock(&im->ino_lock);
	e = radix_tree_lookup(&im->ino_root, ino);
	if (e) {
		list_del(&e->list);
		radix_tree_delete(&im->ino_root, ino);
		im->ino_num--;
		spin_unlock(&im->ino_lock);
		kmem_cache_free(ino_entry_slab, e);
		return;
	}
	spin_unlock(&im->ino_lock);
}

// 添加一个inode管理数据
void f2fs_add_ino_entry(struct f2fs_sb_info *sbi, nid_t ino, int type)
{
	/* add new dirty ino entry into list */
	__add_ino_entry(sbi, ino, 0, type);
}

// 删除一个inode管理数据
void f2fs_remove_ino_entry(struct f2fs_sb_info *sbi, nid_t ino, int type)
{
	/* remove dirty ino entry from list */
	__remove_ino_entry(sbi, ino, type);
}

/* mode should be APPEND_INO, UPDATE_INO or TRANS_DIR_INO */
bool f2fs_exist_written_data(struct f2fs_sb_info *sbi, nid_t ino, int mode)
{
	struct inode_management *im = &sbi->im[mode];
	struct ino_entry *e;

	spin_lock(&im->ino_lock);
	e = radix_tree_lookup(&im->ino_root, ino);
	spin_unlock(&im->ino_lock);
	return e ? true : false;
}

// 释放一个inode管理数据
void f2fs_release_ino_entry(struct f2fs_sb_info *sbi, bool all)
{
	struct ino_entry *e, *tmp;
	int i;

	for (i = all ? ORPHAN_INO : APPEND_INO; i < MAX_INO_ENTRY; i++) {
		struct inode_management *im = &sbi->im[i];

		spin_lock(&im->ino_lock);
		list_for_each_entry_safe(e, tmp, &im->ino_list, list) {
			list_del(&e->list);
			radix_tree_delete(&im->ino_root, e->ino);
			kmem_cache_free(ino_entry_slab, e);
			im->ino_num--;
		}
		spin_unlock(&im->ino_lock);
	}
}

// 设置设备的状态为脏，用于fsync/CP流程下刷设备cache
void f2fs_set_dirty_device(struct f2fs_sb_info *sbi, nid_t ino,
					unsigned int devidx, int type)
{
	// 将脏inode添加到inode管理结构体中
	__add_ino_entry(sbi, ino, devidx, type);
}

// 判断一个设备是否为脏（是否有脏inode页）
bool f2fs_is_dirty_device(struct f2fs_sb_info *sbi, nid_t ino,
					unsigned int devidx, int type)
{
	struct inode_management *im = &sbi->im[type];
	struct ino_entry *e;
	bool is_dirty = false;

	spin_lock(&im->ino_lock);
	e = radix_tree_lookup(&im->ino_root, ino);
	if (e && f2fs_test_bit(devidx, (char *)&e->dirty_device))
		is_dirty = true;
	spin_unlock(&im->ino_lock);
	return is_dirty;
}

int f2fs_acquire_orphan_inode(struct f2fs_sb_info *sbi)
{
	struct inode_management *im = &sbi->im[ORPHAN_INO];
	int err = 0;

	spin_lock(&im->ino_lock);

	if (time_to_inject(sbi, FAULT_ORPHAN)) {
		spin_unlock(&im->ino_lock);
		return -ENOSPC;
	}

	if (unlikely(im->ino_num >= sbi->max_orphans))
		err = -ENOSPC;
	else
		im->ino_num++;
	spin_unlock(&im->ino_lock);

	return err;
}

// 从inode管理cache中释放一个孤儿inode
void f2fs_release_orphan_inode(struct f2fs_sb_info *sbi)
{
	struct inode_management *im = &sbi->im[ORPHAN_INO];

	spin_lock(&im->ino_lock);
	f2fs_bug_on(sbi, im->ino_num == 0);
	im->ino_num--;
	spin_unlock(&im->ino_lock);
}

// 添加一个孤儿inode
void f2fs_add_orphan_inode(struct inode *inode)
{
	/* add new orphan ino entry into list */
	__add_ino_entry(F2FS_I_SB(inode), inode->i_ino, 0, ORPHAN_INO);
	f2fs_update_inode_page(inode);
}

// 移除一个孤儿inode
void f2fs_remove_orphan_inode(struct f2fs_sb_info *sbi, nid_t ino)
{
	/* remove orphan entry from orphan list */
	__remove_ino_entry(sbi, ino, ORPHAN_INO);
}

// 恢复一个孤儿inode，其实就是将孤儿inode进行truncate
static int recover_orphan_inode(struct f2fs_sb_info *sbi, nid_t ino)
{
	struct inode *inode;
	struct node_info ni;
	int err;

	inode = f2fs_iget_retry(sbi->sb, ino);
	if (IS_ERR(inode)) {
		/*
		 * there should be a bug that we can't find the entry
		 * to orphan inode.
		 */
		f2fs_bug_on(sbi, PTR_ERR(inode) == -ENOENT);
		return PTR_ERR(inode);
	}

	err = f2fs_dquot_initialize(inode);
	if (err) {
		iput(inode);
		goto err_out;
	}

	clear_nlink(inode);

	/* truncate all the data during iput */
	iput(inode);

	err = f2fs_get_node_info(sbi, ino, &ni, false);
	if (err)
		goto err_out;

	/* ENOMEM was fully retried in f2fs_evict_inode. */
	if (ni.blk_addr != NULL_ADDR) {
		err = -EIO;
		goto err_out;
	}
	return 0;

err_out:
	set_sbi_flag(sbi, SBI_NEED_FSCK);
	f2fs_warn(sbi, "%s: orphan failed (ino=%x), run fsck to fix.",
		  __func__, ino);
	return err;
}

// 从CP区域中恢复孤儿inode
int f2fs_recover_orphan_inodes(struct f2fs_sb_info *sbi)
{
	block_t start_blk, orphan_blocks, i, j;
	unsigned int s_flags = sbi->sb->s_flags;
	int err = 0;
#ifdef CONFIG_QUOTA
	int quota_enabled;
#endif

	if (!is_set_ckpt_flags(sbi, CP_ORPHAN_PRESENT_FLAG))
		return 0;

	if (bdev_read_only(sbi->sb->s_bdev)) {
		f2fs_info(sbi, "write access unavailable, skipping orphan cleanup");
		return 0;
	}

	if (s_flags & SB_RDONLY) {
		f2fs_info(sbi, "orphan cleanup on readonly fs");
		sbi->sb->s_flags &= ~SB_RDONLY;
	}

#ifdef CONFIG_QUOTA
	/*
	 * Turn on quotas which were not enabled for read-only mounts if
	 * filesystem has quota feature, so that they are updated correctly.
	 */
	quota_enabled = f2fs_enable_quota_files(sbi, s_flags & SB_RDONLY);
#endif

	start_blk = __start_cp_addr(sbi) + 1 + __cp_payload(sbi);
	orphan_blocks = __start_sum_addr(sbi) - 1 - __cp_payload(sbi);

	f2fs_ra_meta_pages(sbi, start_blk, orphan_blocks, META_CP, true);

	for (i = 0; i < orphan_blocks; i++) {
		struct page *page;
		struct f2fs_orphan_block *orphan_blk;

		page = f2fs_get_meta_page(sbi, start_blk + i);
		if (IS_ERR(page)) {
			err = PTR_ERR(page);
			goto out;
		}

		orphan_blk = (struct f2fs_orphan_block *)page_address(page);
		for (j = 0; j < le32_to_cpu(orphan_blk->entry_count); j++) {
			nid_t ino = le32_to_cpu(orphan_blk->ino[j]);

			err = recover_orphan_inode(sbi, ino);
			if (err) {
				f2fs_put_page(page, 1);
				goto out;
			}
		}
		f2fs_put_page(page, 1);
	}
	/* clear Orphan Flag */
	clear_ckpt_flags(sbi, CP_ORPHAN_PRESENT_FLAG);
out:
	set_sbi_flag(sbi, SBI_IS_RECOVERED);

#ifdef CONFIG_QUOTA
	/* Turn quotas off */
	if (quota_enabled)
		f2fs_quota_off_umount(sbi->sb);
#endif
	sbi->sb->s_flags = s_flags; /* Restore SB_RDONLY status */

	return err;
}

// 写入孤儿inode到CP区域中
static void write_orphan_inodes(struct f2fs_sb_info *sbi, block_t start_blk)
{
	struct list_head *head;
	struct f2fs_orphan_block *orphan_blk = NULL;
	unsigned int nentries = 0;
	unsigned short index = 1;
	unsigned short orphan_blocks;
	struct page *page = NULL;
	struct ino_entry *orphan = NULL;
	struct inode_management *im = &sbi->im[ORPHAN_INO];

	orphan_blocks = GET_ORPHAN_BLOCKS(im->ino_num);

	/*
	 * we don't need to do spin_lock(&im->ino_lock) here, since all the
	 * orphan inode operations are covered under f2fs_lock_op().
	 * And, spin_lock should be avoided due to page operations below.
	 */
	head = &im->ino_list;

	/* loop for each orphan inode entry and write them in journal block */
	list_for_each_entry(orphan, head, list) {
		if (!page) {
			page = f2fs_grab_meta_page(sbi, start_blk++);
			orphan_blk =
				(struct f2fs_orphan_block *)page_address(page);
			memset(orphan_blk, 0, sizeof(*orphan_blk));
		}

		orphan_blk->ino[nentries++] = cpu_to_le32(orphan->ino);

		if (nentries == F2FS_ORPHANS_PER_BLOCK) {
			/*
			 * an orphan block is full of 1020 entries,
			 * then we need to flush current orphan blocks
			 * and bring another one in memory
			 */
			orphan_blk->blk_addr = cpu_to_le16(index);
			orphan_blk->blk_count = cpu_to_le16(orphan_blocks);
			orphan_blk->entry_count = cpu_to_le32(nentries);
			set_page_dirty(page);
			f2fs_put_page(page, 1);
			index++;
			nentries = 0;
			page = NULL;
		}
	}

	if (page) {
		orphan_blk->blk_addr = cpu_to_le16(index);
		orphan_blk->blk_count = cpu_to_le16(orphan_blocks);
		orphan_blk->entry_count = cpu_to_le32(nentries);
		set_page_dirty(page);
		f2fs_put_page(page, 1);
	}
}

// 计算某个CP pack的crc值
static __u32 f2fs_checkpoint_chksum(struct f2fs_sb_info *sbi,
						struct f2fs_checkpoint *ckpt)
{
	unsigned int chksum_ofs = le32_to_cpu(ckpt->checksum_offset);
	__u32 chksum;

	chksum = f2fs_crc32(sbi, ckpt, chksum_ofs);
	if (chksum_ofs < CP_CHKSUM_OFFSET) {
		chksum_ofs += sizeof(chksum);
		chksum = f2fs_chksum(sbi, chksum, (__u8 *)ckpt + chksum_ofs,
						F2FS_BLKSIZE - chksum_ofs);
	}
	return chksum;
}

static int get_checkpoint_version(struct f2fs_sb_info *sbi, block_t cp_addr,
		struct f2fs_checkpoint **cp_block, struct page **cp_page,
		unsigned long long *version)
{
	size_t crc_offset = 0;
	__u32 crc;

	// 获取CP pack 1的page，从中获取该CP的版本号
	*cp_page = f2fs_get_meta_page(sbi, cp_addr);
	if (IS_ERR(*cp_page))
		return PTR_ERR(*cp_page);

	*cp_block = (struct f2fs_checkpoint *)page_address(*cp_page);

	// 获取CP pack 1中crc的偏移
	crc_offset = le32_to_cpu((*cp_block)->checksum_offset);
	if (crc_offset < CP_MIN_CHKSUM_OFFSET ||
			crc_offset > CP_CHKSUM_OFFSET) {
		f2fs_put_page(*cp_page, 1);
		f2fs_warn(sbi, "invalid crc_offset: %zu", crc_offset);
		return -EINVAL;
	}

	// 计算CP pack 1的crc，并与记录在CP pack1中的对比，这样可以保护CP是否
	// 被篡改
	crc = f2fs_checkpoint_chksum(sbi, *cp_block);
	if (crc != cur_cp_crc(*cp_block)) {
		f2fs_put_page(*cp_page, 1);
		f2fs_warn(sbi, "invalid crc value");
		return -EINVAL;
	}

	// crc校验通过后，获取cp版本号
	*version = cur_cp_version(*cp_block);
	return 0;
}

static struct page *validate_checkpoint(struct f2fs_sb_info *sbi,
				block_t cp_addr, unsigned long long *version)
{
	struct page *cp_page_1 = NULL, *cp_page_2 = NULL;
	struct f2fs_checkpoint *cp_block = NULL;
	unsigned long long cur_version = 0, pre_version = 0;
	unsigned int cp_blocks;
	int err;

	// 获取CP pack 1的cp版本号
	err = get_checkpoint_version(sbi, cp_addr, &cp_block,
					&cp_page_1, version);
	if (err)
		return NULL;

	cp_blocks = le32_to_cpu(cp_block->cp_pack_total_block_count);

	// 校验cp中记录的cp区域所占用的block数是否合法
	if (cp_blocks > sbi->blocks_per_seg || cp_blocks <= F2FS_CP_PACKS) {
		f2fs_warn(sbi, "invalid cp_pack_total_block_count:%u",
			  le32_to_cpu(cp_block->cp_pack_total_block_count));
		goto invalid_cp;
	}
	pre_version = *version;

	cp_addr += cp_blocks - 1;
	// 获取CP pack 2的cp版本号
	err = get_checkpoint_version(sbi, cp_addr, &cp_block,
					&cp_page_2, version);
	if (err)
		goto invalid_cp;
	cur_version = *version;

	// 如果CP pack 1和CP pack 2的版本号不一致，表示该CP异常，无法保证一致性，需要
	// 丢弃该CP区域
	if (cur_version == pre_version) {
		*version = cur_version;
		f2fs_put_page(cp_page_2, 1);
		return cp_page_1;
	}
	f2fs_put_page(cp_page_2, 1);
invalid_cp:
	f2fs_put_page(cp_page_1, 1);
	return NULL;
}

// 获取一个合法的CP到sbi中，恢复到最新一次的持久化状态，在挂载中调用
int f2fs_get_valid_checkpoint(struct f2fs_sb_info *sbi)
{
	struct f2fs_checkpoint *cp_block;
	struct f2fs_super_block *fsb = sbi->raw_super;
	struct page *cp1, *cp2, *cur_page;
	unsigned long blk_size = sbi->blocksize;
	unsigned long long cp1_version = 0, cp2_version = 0;
	unsigned long long cp_start_blk_no;
	unsigned int cp_blks = 1 + __cp_payload(sbi);
	block_t cp_blk_no;
	int i;
	int err;

	// 申请CP管理结构体
	sbi->ckpt = f2fs_kvzalloc(sbi, array_size(blk_size, cp_blks),
				  GFP_KERNEL);
	if (!sbi->ckpt)
		return -ENOMEM;
	/*
	 * Finding out valid cp block involves read both
	 * sets( cp pack 1 and cp pack 2)
	 */
	// 获取CP区域1的地址
	cp_start_blk_no = le32_to_cpu(fsb->cp_blkaddr);
	// 获取并校验CP区域1的CP是否可用（两个cp block的版本号是否一致）
	cp1 = validate_checkpoint(sbi, cp_start_blk_no, &cp1_version);

	/* The second checkpoint pack should start at the next segment */
	// 获取CP区域2的地址
	cp_start_blk_no += ((unsigned long long)1) <<
				le32_to_cpu(fsb->log_blocks_per_seg);
	// 获取并校验CP区域2的CP是否可用（两个cp block的版本号是否一致）
	cp2 = validate_checkpoint(sbi, cp_start_blk_no, &cp2_version);

	// 如果两个CP都合法，则使用版本号大的那个；如果任一个CP非法，则使用另外
	// 一个CP，如果两个CP都非法，则出错
	if (cp1 && cp2) {
		if (ver_after(cp2_version, cp1_version))
			cur_page = cp2;
		else
			cur_page = cp1;
	} else if (cp1) {
		cur_page = cp1;
	} else if (cp2) {
		cur_page = cp2;
	} else {
		err = -EFSCORRUPTED;
		goto fail_no_cp;
	}

	// 将选定的CP拷贝到sbi中，恢复最新一次持久化成功的状态
	cp_block = (struct f2fs_checkpoint *)page_address(cur_page);
	memcpy(sbi->ckpt, cp_block, blk_size);

	if (cur_page == cp1)
		sbi->cur_cp_pack = 1;
	else
		sbi->cur_cp_pack = 2;

	/* Sanity checking of checkpoint */
	// 静态校验cp内容的合法性
	if (f2fs_sanity_check_ckpt(sbi)) {
		err = -EFSCORRUPTED;
		goto free_fail_no_cp;
	}

	if (cp_blks <= 1)
		goto done;

	cp_blk_no = le32_to_cpu(fsb->cp_blkaddr);
	if (cur_page == cp2)
		cp_blk_no += 1 << le32_to_cpu(fsb->log_blocks_per_seg);

	// 跳过CP pack 1，将剩下的CP内容拷贝到sbi中
	for (i = 1; i < cp_blks; i++) {
		void *sit_bitmap_ptr;
		unsigned char *ckpt = (unsigned char *)sbi->ckpt;

		cur_page = f2fs_get_meta_page(sbi, cp_blk_no + i);
		if (IS_ERR(cur_page)) {
			err = PTR_ERR(cur_page);
			goto free_fail_no_cp;
		}
		sit_bitmap_ptr = page_address(cur_page);
		memcpy(ckpt + i * blk_size, sit_bitmap_ptr, blk_size);
		f2fs_put_page(cur_page, 1);
	}
done:
	f2fs_put_page(cp1, 1);
	f2fs_put_page(cp2, 1);
	return 0;

free_fail_no_cp:
	f2fs_put_page(cp1, 1);
	f2fs_put_page(cp2, 1);
fail_no_cp:
	kvfree(sbi->ckpt);
	return err;
}

// 添加一个dirty inode到链表
static void __add_dirty_inode(struct inode *inode, enum inode_type type)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int flag = (type == DIR_INODE) ? FI_DIRTY_DIR : FI_DIRTY_FILE;

	if (is_inode_flag_set(inode, flag))
		return;

	set_inode_flag(inode, flag);
	list_add_tail(&F2FS_I(inode)->dirty_list, &sbi->inode_list[type]);
	stat_inc_dirty_inode(sbi, type);
}

// 将inode从dirty list中移除
static void __remove_dirty_inode(struct inode *inode, enum inode_type type)
{
	int flag = (type == DIR_INODE) ? FI_DIRTY_DIR : FI_DIRTY_FILE;

	if (get_dirty_pages(inode) || !is_inode_flag_set(inode, flag))
		return;

	list_del_init(&F2FS_I(inode)->dirty_list);
	clear_inode_flag(inode, flag);
	stat_dec_dirty_inode(F2FS_I_SB(inode), type);
}

// 将一个脏inode放入到inode_list中，该接口只处理目录、文件、链接相关的inode，
// 只有当目录类型或者设置了DATA_FLUSH，才会添加到链表中
void f2fs_update_dirty_folio(struct inode *inode, struct folio *folio)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	enum inode_type type = S_ISDIR(inode->i_mode) ? DIR_INODE : FILE_INODE;

	if (!S_ISDIR(inode->i_mode) && !S_ISREG(inode->i_mode) &&
			!S_ISLNK(inode->i_mode))
		return;

	spin_lock(&sbi->inode_lock[type]);
	if (type != FILE_INODE || test_opt(sbi, DATA_FLUSH))
		__add_dirty_inode(inode, type);
	inode_inc_dirty_pages(inode);
	spin_unlock(&sbi->inode_lock[type]);

	set_page_private_reference(&folio->page);
}

// 从inode_list管理链表中移除一个dirty inode，该接口只支持移除
// 目录、文件、链接相关的inode
void f2fs_remove_dirty_inode(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	enum inode_type type = S_ISDIR(inode->i_mode) ? DIR_INODE : FILE_INODE;

	if (!S_ISDIR(inode->i_mode) && !S_ISREG(inode->i_mode) &&
			!S_ISLNK(inode->i_mode))
		return;

	if (type == FILE_INODE && !test_opt(sbi, DATA_FLUSH))
		return;

	spin_lock(&sbi->inode_lock[type]);
	__remove_dirty_inode(inode, type);
	spin_unlock(&sbi->inode_lock[type]);
}

int f2fs_sync_dirty_inodes(struct f2fs_sb_info *sbi, enum inode_type type,
						bool from_cp)
{
	struct list_head *head;
	struct inode *inode;
	struct f2fs_inode_info *fi;
	bool is_dir = (type == DIR_INODE);
	unsigned long ino = 0;

	trace_f2fs_sync_dirty_inodes_enter(sbi->sb, is_dir,
				get_pages(sbi, is_dir ?
				F2FS_DIRTY_DENTS : F2FS_DIRTY_DATA));
retry:
	if (unlikely(f2fs_cp_error(sbi))) {
		trace_f2fs_sync_dirty_inodes_exit(sbi->sb, is_dir,
				get_pages(sbi, is_dir ?
				F2FS_DIRTY_DENTS : F2FS_DIRTY_DATA));
		return -EIO;
	}

	spin_lock(&sbi->inode_lock[type]);

	// 根据需要下刷的类型获取脏inode列表
	head = &sbi->inode_list[type];
	if (list_empty(head)) {
		spin_unlock(&sbi->inode_lock[type]);
		trace_f2fs_sync_dirty_inodes_exit(sbi->sb, is_dir,
				get_pages(sbi, is_dir ?
				F2FS_DIRTY_DENTS : F2FS_DIRTY_DATA));
		return 0;
	}
	// 获取f2fs的inode管理数据结构
	fi = list_first_entry(head, struct f2fs_inode_info, dirty_list);
	inode = igrab(&fi->vfs_inode);
	spin_unlock(&sbi->inode_lock[type]);
	if (inode) {
		unsigned long cur_ino = inode->i_ino;

		// TODO:为什么要记录cp_task
		if (from_cp)
			F2FS_I(inode)->cp_task = current;
		F2FS_I(inode)->wb_task = current;

		// 将挂在inode下的data数据下刷
		filemap_fdatawrite(inode->i_mapping);

		F2FS_I(inode)->wb_task = NULL;
		if (from_cp)
			F2FS_I(inode)->cp_task = NULL;

		iput(inode);
		/* We need to give cpu to another writers. */
		if (ino == cur_ino)
			cond_resched();
		else
			ino = cur_ino;
	} else {
		/*
		 * We should submit bio, since it exists several
		 * writebacking dentry pages in the freeing inode.
		 */
		f2fs_submit_merged_write(sbi, DATA);
		cond_resched();
	}
	goto retry;
}

// 下刷管理相关的元数据
int f2fs_sync_inode_meta(struct f2fs_sb_info *sbi)
{
	// 获取所有脏的元数据inode
	struct list_head *head = &sbi->inode_list[DIRTY_META];
	struct inode *inode;
	struct f2fs_inode_info *fi;
	// 获取所有脏的元数据inode数量
	s64 total = get_pages(sbi, F2FS_DIRTY_IMETA);

	// 遍历脏元数据inode
	while (total--) {
		if (unlikely(f2fs_cp_error(sbi)))
			return -EIO;

		spin_lock(&sbi->inode_lock[DIRTY_META]);
		if (list_empty(head)) {
			spin_unlock(&sbi->inode_lock[DIRTY_META]);
			return 0;
		}
		fi = list_first_entry(head, struct f2fs_inode_info,
							gdirty_list);
		inode = igrab(&fi->vfs_inode);
		spin_unlock(&sbi->inode_lock[DIRTY_META]);
		if (inode) {
			// 通过vfs层接口，下刷元数据
			sync_inode_metadata(inode, 0);

			/* it's on eviction */
			if (is_inode_flag_set(inode, FI_DIRTY_INODE))
				f2fs_update_inode_page(inode);
			iput(inode);
		}
	}
	return 0;
}

// 将sbi中的部分数据更新到cp结构体中，准备写cp block
static void __prepare_cp_block(struct f2fs_sb_info *sbi)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	nid_t last_nid = nm_i->next_scan_nid;

	next_free_nid(sbi, &last_nid);
	ckpt->valid_block_count = cpu_to_le64(valid_user_blocks(sbi));
	ckpt->valid_node_count = cpu_to_le32(valid_node_count(sbi));
	ckpt->valid_inode_count = cpu_to_le32(valid_inode_count(sbi));
	ckpt->next_free_nid = cpu_to_le32(last_nid);
}

// TODO：与quota相关
static bool __need_flush_quota(struct f2fs_sb_info *sbi)
{
	bool ret = false;

	if (!is_journalled_quota(sbi))
		return false;

	if (!f2fs_down_write_trylock(&sbi->quota_sem))
		return true;
	if (is_sbi_flag_set(sbi, SBI_QUOTA_SKIP_FLUSH)) {
		ret = false;
	} else if (is_sbi_flag_set(sbi, SBI_QUOTA_NEED_REPAIR)) {
		ret = false;
	} else if (is_sbi_flag_set(sbi, SBI_QUOTA_NEED_FLUSH)) {
		clear_sbi_flag(sbi, SBI_QUOTA_NEED_FLUSH);
		ret = true;
	} else if (get_pages(sbi, F2FS_DIRTY_QDATA)) {
		ret = true;
	}
	f2fs_up_write(&sbi->quota_sem);
	return ret;
}

/*
 * Freeze all the FS-operations for checkpoint.
 */
static int block_operations(struct f2fs_sb_info *sbi)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = LONG_MAX,
		.for_reclaim = 0,
	};
	int err = 0, cnt = 0;

	/*
	 * Let's flush inline_data in dirty node pages.
	 */
	// 将inode的dirty inline数据下刷，在fsync时候只下刷了data,
	// 并没有处理inline data
	f2fs_flush_inline_data(sbi);

retry_flush_quotas:
	// 上CP锁，不允许再进行改动管理数据的行为
	f2fs_lock_all(sbi);
	// TODO:与quota有关
	if (__need_flush_quota(sbi)) {
		int locked;

		if (++cnt > DEFAULT_RETRY_QUOTA_FLUSH_COUNT) {
			set_sbi_flag(sbi, SBI_QUOTA_SKIP_FLUSH);
			set_sbi_flag(sbi, SBI_QUOTA_NEED_FLUSH);
			goto retry_flush_dents;
		}
		f2fs_unlock_all(sbi);

		/* only failed during mount/umount/freeze/quotactl */
		locked = down_read_trylock(&sbi->sb->s_umount);
		f2fs_quota_sync(sbi->sb, -1);
		if (locked)
			up_read(&sbi->sb->s_umount);
		cond_resched();
		goto retry_flush_quotas;
	}

retry_flush_dents:
	/* write all the dirty dentry pages */
	// 下刷所有脏dentry页，fsync并没有处理dir的data数据，只下刷了文件的data
	// 数据，在此处将dir的data数据下刷
	if (get_pages(sbi, F2FS_DIRTY_DENTS)) {
		f2fs_unlock_all(sbi);
		err = f2fs_sync_dirty_inodes(sbi, DIR_INODE, true);
		if (err)
			return err;
		cond_resched();
		goto retry_flush_quotas;
	}

	/*
	 * POR: we should ensure that there are no dirty node pages
	 * until finishing nat/sit flush. inode->i_blocks can be updated.
	 */
	f2fs_down_write(&sbi->node_change);

	// 将管理元数据下刷（不属于文件、目录、链接的inode，应该就是元数据inode，例如：
	// acl、attr等等）
	if (get_pages(sbi, F2FS_DIRTY_IMETA)) {
		f2fs_up_write(&sbi->node_change);
		f2fs_unlock_all(sbi);
		err = f2fs_sync_inode_meta(sbi);
		if (err)
			return err;
		cond_resched();
		goto retry_flush_quotas;
	}

retry_flush_nodes:
	f2fs_down_write(&sbi->node_write);

	// fsync流程只下刷了普通文件的node page，配合前滚恢复可以保证一致性;
	// 在CP流程中，将其他类型的noage page下刷，配合后滚恢复保证一致性
	if (get_pages(sbi, F2FS_DIRTY_NODES)) {
		f2fs_up_write(&sbi->node_write);
		atomic_inc(&sbi->wb_sync_req[NODE]);
		err = f2fs_sync_node_pages(sbi, &wbc, false, FS_CP_NODE_IO);
		atomic_dec(&sbi->wb_sync_req[NODE]);
		if (err) {
			f2fs_up_write(&sbi->node_change);
			f2fs_unlock_all(sbi);
			return err;
		}
		cond_resched();
		goto retry_flush_nodes;
	}

	/*
	 * sbi->node_change is used only for AIO write_begin path which produces
	 * dirty node blocks and some checkpoint values by block allocation.
	 */
	// 将sbi中的部分数据更新到cp结构体中，准备写cp block
	__prepare_cp_block(sbi);
	f2fs_up_write(&sbi->node_change);
	return err;
}

// 解除阻塞写操作
static void unblock_operations(struct f2fs_sb_info *sbi)
{
	f2fs_up_write(&sbi->node_write);
	f2fs_unlock_all(sbi);
}

// 等待CP任务将某个类型的脏页下刷
void f2fs_wait_on_all_pages(struct f2fs_sb_info *sbi, int type)
{
	DEFINE_WAIT(wait);

	for (;;) {
		if (!get_pages(sbi, type))
			break;

		if (unlikely(f2fs_cp_error(sbi)))
			break;

		if (type == F2FS_DIRTY_META)
			f2fs_sync_meta_pages(sbi, META, LONG_MAX,
							FS_CP_META_IO);
		else if (type == F2FS_WB_CP_DATA)
			f2fs_submit_merged_write(sbi, DATA);

		prepare_to_wait(&sbi->cp_wait, &wait, TASK_UNINTERRUPTIBLE);
		io_schedule_timeout(DEFAULT_IO_TIMEOUT);
	}
	finish_wait(&sbi->cp_wait, &wait);
}

// 根据cp或者sbi中的信息，设置cp对应的标记位
static void update_ckpt_flags(struct f2fs_sb_info *sbi, struct cp_control *cpc)
{
	unsigned long orphan_num = sbi->im[ORPHAN_INO].ino_num;
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	unsigned long flags;

	if (cpc->reason & CP_UMOUNT) {
		if (le32_to_cpu(ckpt->cp_pack_total_block_count) +
			NM_I(sbi)->nat_bits_blocks > sbi->blocks_per_seg) {
			clear_ckpt_flags(sbi, CP_NAT_BITS_FLAG);
			f2fs_notice(sbi, "Disable nat_bits due to no space");
		} else if (!is_set_ckpt_flags(sbi, CP_NAT_BITS_FLAG) &&
						f2fs_nat_bitmap_enabled(sbi)) {
			f2fs_enable_nat_bits(sbi);
			set_ckpt_flags(sbi, CP_NAT_BITS_FLAG);
			f2fs_notice(sbi, "Rebuild and enable nat_bits");
		}
	}

	spin_lock_irqsave(&sbi->cp_lock, flags);

	if (cpc->reason & CP_TRIMMED)
		__set_ckpt_flags(ckpt, CP_TRIMMED_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_TRIMMED_FLAG);

	if (cpc->reason & CP_UMOUNT)
		__set_ckpt_flags(ckpt, CP_UMOUNT_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_UMOUNT_FLAG);

	if (cpc->reason & CP_FASTBOOT)
		__set_ckpt_flags(ckpt, CP_FASTBOOT_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_FASTBOOT_FLAG);

	if (orphan_num)
		__set_ckpt_flags(ckpt, CP_ORPHAN_PRESENT_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_ORPHAN_PRESENT_FLAG);

	if (is_sbi_flag_set(sbi, SBI_NEED_FSCK))
		__set_ckpt_flags(ckpt, CP_FSCK_FLAG);

	if (is_sbi_flag_set(sbi, SBI_IS_RESIZEFS))
		__set_ckpt_flags(ckpt, CP_RESIZEFS_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_RESIZEFS_FLAG);

	if (is_sbi_flag_set(sbi, SBI_CP_DISABLED))
		__set_ckpt_flags(ckpt, CP_DISABLED_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_DISABLED_FLAG);

	if (is_sbi_flag_set(sbi, SBI_CP_DISABLED_QUICK))
		__set_ckpt_flags(ckpt, CP_DISABLED_QUICK_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_DISABLED_QUICK_FLAG);

	if (is_sbi_flag_set(sbi, SBI_QUOTA_SKIP_FLUSH))
		__set_ckpt_flags(ckpt, CP_QUOTA_NEED_FSCK_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_QUOTA_NEED_FSCK_FLAG);

	if (is_sbi_flag_set(sbi, SBI_QUOTA_NEED_REPAIR))
		__set_ckpt_flags(ckpt, CP_QUOTA_NEED_FSCK_FLAG);

	/* set this flag to activate crc|cp_ver for recovery */
	__set_ckpt_flags(ckpt, CP_CRC_RECOVERY_FLAG);
	__clear_ckpt_flags(ckpt, CP_NOCRC_RECOVERY_FLAG);

	spin_unlock_irqrestore(&sbi->cp_lock, flags);
}

// 提交本次CP，也即写入CP pack 2的block
static void commit_checkpoint(struct f2fs_sb_info *sbi,
	void *src, block_t blk_addr)
{
	struct writeback_control wbc = {
		.for_reclaim = 0,
	};

	/*
	 * filemap_get_folios_tag and lock_page again will take
	 * some extra time. Therefore, f2fs_update_meta_pages and
	 * f2fs_sync_meta_pages are combined in this function.
	 */
	// 获取cp pack 2的page
	struct page *page = f2fs_grab_meta_page(sbi, blk_addr);
	int err;

	// 等待该page下刷完成
	f2fs_wait_on_page_writeback(page, META, true, true);

	// 将内存中的cp写入page
	memcpy(page_address(page), src, PAGE_SIZE);

	// 设置page为dirty
	set_page_dirty(page);
	if (unlikely(!clear_page_dirty_for_io(page)))
		f2fs_bug_on(sbi, 1);

	/* writeout cp pack 2 page */
	// 将cp 2落盘
	err = __f2fs_write_meta_page(page, &wbc, FS_CP_META_IO);
	if (unlikely(err && f2fs_cp_error(sbi))) {
		f2fs_put_page(page, 1);
		return;
	}

	f2fs_bug_on(sbi, err);
	f2fs_put_page(page, 0);

	/* submit checkpoint (with barrier if NOBARRIER is not set) */
	f2fs_submit_merged_write(sbi, META_FLUSH);
}

// 获取单个设备已经写入的block数
static inline u64 get_sectors_written(struct block_device *bdev)
{
	return (u64)part_stat_read(bdev, sectors[STAT_WRITE]);
}

// 获取各个设备已经写入的block数
u64 f2fs_get_sectors_written(struct f2fs_sb_info *sbi)
{
	if (f2fs_is_multi_device(sbi)) {
		u64 sectors = 0;
		int i;

		for (i = 0; i < sbi->s_ndevs; i++)
			sectors += get_sectors_written(FDEV(i).bdev);

		return sectors;
	}

	return get_sectors_written(sbi->sb->s_bdev);
}

static int do_checkpoint(struct f2fs_sb_info *sbi, struct cp_control *cpc)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned long orphan_num = sbi->im[ORPHAN_INO].ino_num, flags;
	block_t start_blk;
	unsigned int data_sum_blocks, orphan_blocks;
	__u32 crc32 = 0;
	int i;
	int cp_payload_blks = __cp_payload(sbi);
	struct curseg_info *seg_i = CURSEG_I(sbi, CURSEG_HOT_NODE);
	u64 kbytes_written;
	int err;

	/* Flush all the NAT/SIT pages */
	// 将NAT/SIT的cache下刷（上面下刷的是meta inode）
	f2fs_sync_meta_pages(sbi, META, LONG_MAX, FS_CP_META_IO);

	/* start to update checkpoint, cp ver is already updated previously */
	// 将sbi中的信息更新到CP中，包括更新间隔，空闲segment数目，当前各个segment的使用情况等等
	ckpt->elapsed_time = cpu_to_le64(get_mtime(sbi, true));
	ckpt->free_segment_count = cpu_to_le32(free_segments(sbi));
	for (i = 0; i < NR_CURSEG_NODE_TYPE; i++) {
		struct curseg_info *curseg = CURSEG_I(sbi, i + CURSEG_HOT_NODE);

		ckpt->cur_node_segno[i] = cpu_to_le32(curseg->segno);
		ckpt->cur_node_blkoff[i] = cpu_to_le16(curseg->next_blkoff);
		ckpt->alloc_type[i + CURSEG_HOT_NODE] = curseg->alloc_type;
	}
	for (i = 0; i < NR_CURSEG_DATA_TYPE; i++) {
		struct curseg_info *curseg = CURSEG_I(sbi, i + CURSEG_HOT_DATA);

		ckpt->cur_data_segno[i] = cpu_to_le32(curseg->segno);
		ckpt->cur_data_blkoff[i] = cpu_to_le16(curseg->next_blkoff);
		ckpt->alloc_type[i + CURSEG_HOT_DATA] = curseg->alloc_type;
	}

	/* 2 cp + n data seg summary + orphan inode blocks */
	// 计算data类型的segment的SSA区域占的block数
	data_sum_blocks = f2fs_npages_for_summary_flush(sbi, false);
	spin_lock_irqsave(&sbi->cp_lock, flags);
	// 如果data类型的segment的SSA区域数小于3，表示进行了压缩，设置对应的标记;
	// 否则清除对应标记
	if (data_sum_blocks < NR_CURSEG_DATA_TYPE)
		__set_ckpt_flags(ckpt, CP_COMPACT_SUM_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_COMPACT_SUM_FLAG);
	spin_unlock_irqrestore(&sbi->cp_lock, flags);

	orphan_blocks = GET_ORPHAN_BLOCKS(orphan_num);
	// 计算cp pack 1的block数目，分别是1个cp pack + orphan_blocks + cp_payload_blks
	ckpt->cp_pack_start_sum = cpu_to_le32(1 + cp_payload_blks +
			orphan_blocks);

	// 如果非umount或fastboot触发的CP，无需写入node类型segment的SSA信息（配合前滚恢复可以
	// 保证一致性？）
	if (__remain_node_summaries(cpc->reason))
		ckpt->cp_pack_total_block_count = cpu_to_le32(F2FS_CP_PACKS +
				cp_payload_blks + data_sum_blocks +
				orphan_blocks + NR_CURSEG_NODE_TYPE);
	else
		ckpt->cp_pack_total_block_count = cpu_to_le32(F2FS_CP_PACKS +
				cp_payload_blks + data_sum_blocks +
				orphan_blocks);

	/* update ckpt flag for checkpoint */
	// 根据前面写入的信息和sbi中的标记位，设置cp对应标记
	update_ckpt_flags(sbi, cpc);

	/* update SIT/NAT bitmap */
	// 将sbi中的SIT/NAT bitmap写入cp pack的sit_nat_version_bitmap，
	// 下次可以直接恢复对应的管理信息
	get_sit_bitmap(sbi, __bitmap_ptr(sbi, SIT_BITMAP));
	get_nat_bitmap(sbi, __bitmap_ptr(sbi, NAT_BITMAP));

	// 计算cp的crc32
	crc32 = f2fs_checkpoint_chksum(sbi, ckpt);
	*((__le32 *)((unsigned char *)ckpt +
				le32_to_cpu(ckpt->checksum_offset)))
				= cpu_to_le32(crc32);

	// 获取本次写cp的起始地址（两个区域轮流使用）
	start_blk = __start_cp_next_addr(sbi);

	/* write nat bits */
	// TODO：此处的作用是啥？
	if ((cpc->reason & CP_UMOUNT) &&
			is_set_ckpt_flags(sbi, CP_NAT_BITS_FLAG)) {
		__u64 cp_ver = cur_cp_version(ckpt);
		block_t blk;

		cp_ver |= ((__u64)crc32 << 32);
		*(__le64 *)nm_i->nat_bits = cpu_to_le64(cp_ver);

		blk = start_blk + sbi->blocks_per_seg - nm_i->nat_bits_blocks;
		for (i = 0; i < nm_i->nat_bits_blocks; i++)
			f2fs_update_meta_page(sbi, nm_i->nat_bits +
					(i << F2FS_BLKSIZE_BITS), blk + i);
	}

	/* write out checkpoint buffer at block 0 */
	// 写入cp pack 1在CP区域的0号block
	f2fs_update_meta_page(sbi, ckpt, start_blk++);

	// 写入填充信息，填充信息应该是mkfs.f2fs的时候指定的
	for (i = 1; i < 1 + cp_payload_blks; i++)
		f2fs_update_meta_page(sbi, (char *)ckpt + i * F2FS_BLKSIZE,
							start_blk++);

	// 如果有孤儿inode,则接着写入
	if (orphan_num) {
		write_orphan_inodes(sbi, start_blk);
		start_blk += orphan_blocks;
	}

	// 写data segment的SSA信息，可能经过了压缩
	f2fs_write_data_summaries(sbi, start_blk);
	start_blk += data_sum_blocks;

	/* Record write statistics in the hot node summary */
	// 记录写入的hot node的summary静态信息
	kbytes_written = sbi->kbytes_written;
	kbytes_written += (f2fs_get_sectors_written(sbi) -
				sbi->sectors_written_start) >> 1;
	seg_i->journal->info.kbytes_written = cpu_to_le64(kbytes_written);

	// 如果因umount或fastboot触发的CP，则写入node segment的SSA信息
	if (__remain_node_summaries(cpc->reason)) {
		f2fs_write_node_summaries(sbi, start_blk);
		start_blk += NR_CURSEG_NODE_TYPE;
	}

	/* update user_block_counts */
	// 更新上一次CP时的系统使用了的block数
	sbi->last_valid_block_count = sbi->total_valid_block_count;
	percpu_counter_set(&sbi->alloc_valid_block_count, 0);
	percpu_counter_set(&sbi->rf_node_block_count, 0);

	/* Here, we have one bio having CP pack except cp pack 2 page */
	// 将上述写的元数据落盘，除了CP 2
	f2fs_sync_meta_pages(sbi, META, LONG_MAX, FS_CP_META_IO);
	/* Wait for all dirty meta pages to be submitted for IO */
	f2fs_wait_on_all_pages(sbi, F2FS_DIRTY_META);

	/* wait for previous submitted meta pages writeback */
	// 等待元数据落盘
	f2fs_wait_on_all_pages(sbi, F2FS_WB_CP_DATA);

	/* flush all device cache */
	// 对设备下发flush命令，确保已经写入到设备cache中的数据能最终落盘;
	// 该操作需要在写CP 2前执行，否则可能CP 2先写入了，而其他元数据还没
	// 写入，导致系统无法保证一致性
	err = f2fs_flush_device_cache(sbi);
	if (err)
		return err;

	/* barrier and flush checkpoint cp pack 2 page if it can */
	// 提交本次CP，也即写入CP pack 2的block，保证本次CP完整性，只有CP 1和CP 2的版本一致，
	// 该CP区域才可以用于恢复
	commit_checkpoint(sbi, ckpt, start_blk);
	f2fs_wait_on_all_pages(sbi, F2FS_WB_CP_DATA);

	/*
	 * invalidate intermediate page cache borrowed from meta inode which are
	 * used for migration of encrypted, verity or compressed inode's blocks.
	 */
	if (f2fs_sb_has_encrypt(sbi) || f2fs_sb_has_verity(sbi) ||
		f2fs_sb_has_compression(sbi))
		invalidate_mapping_pages(META_MAPPING(sbi),
				MAIN_BLKADDR(sbi), MAX_BLKADDR(sbi) - 1);

	// 释放inode管理的缓存
	f2fs_release_ino_entry(sbi, false);

	// 重置fsync的序列号
	f2fs_reset_fsync_node_info(sbi);

	clear_sbi_flag(sbi, SBI_IS_DIRTY);
	clear_sbi_flag(sbi, SBI_NEED_CP);
	clear_sbi_flag(sbi, SBI_QUOTA_SKIP_FLUSH);

	spin_lock(&sbi->stat_lock);
	sbi->unusable_block_count = 0;
	spin_unlock(&sbi->stat_lock);

	// 设置下一次CP的区域
	__set_cp_next_pack(sbi);

	/*
	 * redirty superblock if metadata like node page or inode cache is
	 * updated during writing checkpoint.
	 */
	if (get_pages(sbi, F2FS_DIRTY_NODES) ||
			get_pages(sbi, F2FS_DIRTY_IMETA))
		set_sbi_flag(sbi, SBI_IS_DIRTY);

	f2fs_bug_on(sbi, get_pages(sbi, F2FS_DIRTY_DENTS));

	return unlikely(f2fs_cp_error(sbi)) ? -EIO : 0;
}

// 执行一次写CP操作
int f2fs_write_checkpoint(struct f2fs_sb_info *sbi, struct cp_control *cpc)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	unsigned long long ckpt_ver;
	int err = 0;

	// 只读文件系统或者只读存储介质，则不涉及CP操作
	if (f2fs_readonly(sbi->sb) || f2fs_hw_is_readonly(sbi))
		return -EROFS;

	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
		if (cpc->reason != CP_PAUSE)
			return 0;
		f2fs_warn(sbi, "Start checkpoint disabled!");
	}

	if (cpc->reason != CP_RESIZE)
		f2fs_down_write(&sbi->cp_global_sem);

	if (!is_sbi_flag_set(sbi, SBI_IS_DIRTY) &&
		((cpc->reason & CP_FASTBOOT) || (cpc->reason & CP_SYNC) ||
		((cpc->reason & CP_DISCARD) && !sbi->discard_blks)))
		goto out;
	if (unlikely(f2fs_cp_error(sbi))) {
		err = -EIO;
		goto out;
	}

	trace_f2fs_write_checkpoint(sbi->sb, cpc->reason, "start block_ops");

	// 阻塞文件系统写操作
	err = block_operations(sbi);
	if (err)
		goto out;

	trace_f2fs_write_checkpoint(sbi->sb, cpc->reason, "finish block_ops");

	// 提交sbi中缓存的bio（可能经过合并了的）
	f2fs_flush_merged_writes(sbi);

	/* this is the case of multiple fstrims without any changes */
	// TODO：discard相关
	if (cpc->reason & CP_DISCARD) {
		if (!f2fs_exist_trim_candidates(sbi, cpc)) {
			unblock_operations(sbi);
			goto out;
		}

		if (NM_I(sbi)->nat_cnt[DIRTY_NAT] == 0 &&
				SIT_I(sbi)->dirty_sentries == 0 &&
				prefree_segments(sbi) == 0) {
			f2fs_flush_sit_entries(sbi, cpc);
			f2fs_clear_prefree_segments(sbi, cpc);
			unblock_operations(sbi);
			goto out;
		}
	}

	/*
	 * update checkpoint pack index
	 * Increase the version number so that
	 * SIT entries and seg summaries are written at correct place
	 */
	// 获取当前的CP版本号
	ckpt_ver = cur_cp_version(ckpt);
	// CP版本号递增
	ckpt->checkpoint_ver = cpu_to_le64(++ckpt_ver);

	/* write cached NAT/SIT entries to NAT/SIT area */
	// 下刷journal中的nat entry cache
	err = f2fs_flush_nat_entries(sbi, cpc);
	if (err) {
		f2fs_err(sbi, "f2fs_flush_nat_entries failed err:%d, stop checkpoint", err);
		f2fs_bug_on(sbi, !f2fs_cp_error(sbi));
		goto stop;
	}

	// 下刷journal中的sit entry cache
	f2fs_flush_sit_entries(sbi, cpc);

	/* save inmem log status */
	// 将pinned文件sum信息下刷
	f2fs_save_inmem_curseg(sbi);

	// 写CP
	err = do_checkpoint(sbi, cpc);
	if (err) {
		f2fs_err(sbi, "do_checkpoint failed err:%d, stop checkpoint", err);
		f2fs_bug_on(sbi, !f2fs_cp_error(sbi));
		f2fs_release_discard_addrs(sbi);
	} else {
		// 将预申请（PRE）的segment释放，在GC场景中，已经搬移了的segment,会暂时设置成
		// 预申请（PRE）状态，通过CP之后才能真正开始使用，否则可能会丢失修改
		f2fs_clear_prefree_segments(sbi, cpc);
	}

	// TODO：恢复pinned文件的sum信息？
	f2fs_restore_inmem_curseg(sbi);
stop:
	// 释放CP锁
	unblock_operations(sbi);
	stat_inc_cp_count(sbi->stat_info);

	if (cpc->reason & CP_RECOVERY)
		f2fs_notice(sbi, "checkpoint: version = %llx", ckpt_ver);

	/* update CP_TIME to trigger checkpoint periodically */
	// 更新最后一次CP的时间
	f2fs_update_time(sbi, CP_TIME);
	trace_f2fs_write_checkpoint(sbi->sb, cpc->reason, "finish checkpoint");
out:
	if (cpc->reason != CP_RESIZE)
		f2fs_up_write(&sbi->cp_global_sem);
	return err;
}

// 初始化inode缓存管理结构体
void f2fs_init_ino_entry_info(struct f2fs_sb_info *sbi)
{
	int i;

	for (i = 0; i < MAX_INO_ENTRY; i++) {
		struct inode_management *im = &sbi->im[i];

		INIT_RADIX_TREE(&im->ino_root, GFP_ATOMIC);
		spin_lock_init(&im->ino_lock);
		INIT_LIST_HEAD(&im->ino_list);
		im->ino_num = 0;
	}

	sbi->max_orphans = (sbi->blocks_per_seg - F2FS_CP_PACKS -
			NR_CURSEG_PERSIST_TYPE - __cp_payload(sbi)) *
				F2FS_ORPHANS_PER_BLOCK;
}

// 创建CP相关的内存分配器
int __init f2fs_create_checkpoint_caches(void)
{
	ino_entry_slab = f2fs_kmem_cache_create("f2fs_ino_entry",
			sizeof(struct ino_entry));
	if (!ino_entry_slab)
		return -ENOMEM;
	f2fs_inode_entry_slab = f2fs_kmem_cache_create("f2fs_inode_entry",
			sizeof(struct inode_entry));
	if (!f2fs_inode_entry_slab) {
		kmem_cache_destroy(ino_entry_slab);
		return -ENOMEM;
	}
	return 0;
}

// 删除内存分配器
void f2fs_destroy_checkpoint_caches(void)
{
	kmem_cache_destroy(ino_entry_slab);
	kmem_cache_destroy(f2fs_inode_entry_slab);
}

// 进行一致性写CP操作
static int __write_checkpoint_sync(struct f2fs_sb_info *sbi)
{
	struct cp_control cpc = { .reason = CP_SYNC, };
	int err;

	f2fs_down_write(&sbi->gc_lock);
	err = f2fs_write_checkpoint(sbi, &cpc);
	f2fs_up_write(&sbi->gc_lock);

	return err;
}

// 写CP并将请求状态置为完成
static void __checkpoint_and_complete_reqs(struct f2fs_sb_info *sbi)
{
	struct ckpt_req_control *cprc = &sbi->cprc_info;
	struct ckpt_req *req, *next;
	struct llist_node *dispatch_list;
	u64 sum_diff = 0, diff, count = 0;
	int ret;

	// 获取整个CP请求链表
	dispatch_list = llist_del_all(&cprc->issue_list);
	if (!dispatch_list)
		return;
	// 对请求链表进行排序
	dispatch_list = llist_reverse_order(dispatch_list);

	// 进行一次写CP操作
	ret = __write_checkpoint_sync(sbi);
	// 已经进行的CP数加1
	atomic_inc(&cprc->issued_ckpt);

	// 遍历请求链表，将所有请求状态都设置成完成，并返回对应的结果
	llist_for_each_entry_safe(req, next, dispatch_list, llnode) {
		diff = (u64)ktime_ms_delta(ktime_get(), req->queue_time);
		req->ret = ret;
		complete(&req->wait);

		sum_diff += diff;
		count++;
	}
	// 更新统计
	atomic_sub(count, &cprc->queued_ckpt);
	atomic_add(count, &cprc->total_ckpt);

	spin_lock(&cprc->stat_lock);
	cprc->cur_time = (unsigned int)div64_u64(sum_diff, count);
	if (cprc->peak_time < cprc->cur_time)
		cprc->peak_time = cprc->cur_time;
	spin_unlock(&cprc->stat_lock);
}

// 通过CP任务出发一次写CP
static int issue_checkpoint_thread(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct ckpt_req_control *cprc = &sbi->cprc_info;
	wait_queue_head_t *q = &cprc->ckpt_wait_queue;
repeat:
	if (kthread_should_stop())
		return 0;

	// 如果写CP任务列表不为空，则进行一次写CP操作
	if (!llist_empty(&cprc->issue_list))
		__checkpoint_and_complete_reqs(sbi);

	// 等待再次被唤醒
	wait_event_interruptible(*q,
		kthread_should_stop() || !llist_empty(&cprc->issue_list));
	goto repeat;
}

// 在本任务进行一次写CP
static void flush_remained_ckpt_reqs(struct f2fs_sb_info *sbi,
		struct ckpt_req *wait_req)
{
	struct ckpt_req_control *cprc = &sbi->cprc_info;

	// 如果写CP任务列表不为空，则进行一次写CP操作
	if (!llist_empty(&cprc->issue_list)) {
		__checkpoint_and_complete_reqs(sbi);
	} else {
		/* already dispatched by issue_checkpoint_thread */
		if (wait_req)
			wait_for_completion(&wait_req->wait);
	}
}

// 初始化一个CP请求结构体
static void init_ckpt_req(struct ckpt_req *req)
{
	memset(req, 0, sizeof(struct ckpt_req));

	init_completion(&req->wait);
	req->queue_time = ktime_get();
}

// 下发CP请求
int f2fs_issue_checkpoint(struct f2fs_sb_info *sbi)
{
	struct ckpt_req_control *cprc = &sbi->cprc_info;
	struct ckpt_req req;
	struct cp_control cpc;

	// 获取本次CP的原因，如果不是umount或者fastboot，都是为了一致性，也就是CP_SYNC
	cpc.reason = __get_cp_reason(sbi);
	// 如果挂载的时候没有指定合并CP，或者CP任务不是由于一致性，则直接在本任务中写CP
	if (!test_opt(sbi, MERGE_CHECKPOINT) || cpc.reason != CP_SYNC) {
		int ret;

		f2fs_down_write(&sbi->gc_lock);
		// 写CP,不走任务的方式
		ret = f2fs_write_checkpoint(sbi, &cpc);
		f2fs_up_write(&sbi->gc_lock);

		return ret;
	}

	// 如果系统没有创建CP任务，则也在本任务中写CP
	if (!cprc->f2fs_issue_ckpt)
		return __write_checkpoint_sync(sbi);

	init_ckpt_req(&req);

	// 将一个CP请求放到CP链表，等待CP任务处理
	llist_add(&req.llnode, &cprc->issue_list);
	// 增加队列任务计数
	atomic_inc(&cprc->queued_ckpt);

	/*
	 * update issue_list before we wake up issue_checkpoint thread,
	 * this smp_mb() pairs with another barrier in ___wait_event(),
	 * see more details in comments of waitqueue_active().
	 */
	smp_mb();

	// 如果CP等待队列非空，唤醒CP任务
	if (waitqueue_active(&cprc->ckpt_wait_queue))
		wake_up(&cprc->ckpt_wait_queue);

	// 等待CP任务完成信号
	if (cprc->f2fs_issue_ckpt)
		wait_for_completion(&req.wait);
	else
		// 如果不支持CP任务，或者已经被停止了，则在本任务下发CP
		flush_remained_ckpt_reqs(sbi, &req);

	return req.ret;
}

// 创建CP任务，系统可以该任务异步写CP
int f2fs_start_ckpt_thread(struct f2fs_sb_info *sbi)
{
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	struct ckpt_req_control *cprc = &sbi->cprc_info;

	if (cprc->f2fs_issue_ckpt)
		return 0;

	cprc->f2fs_issue_ckpt = kthread_run(issue_checkpoint_thread, sbi,
			"f2fs_ckpt-%u:%u", MAJOR(dev), MINOR(dev));
	if (IS_ERR(cprc->f2fs_issue_ckpt)) {
		int err = PTR_ERR(cprc->f2fs_issue_ckpt);

		cprc->f2fs_issue_ckpt = NULL;
		return err;
	}

	// 设置任务优先级
	set_task_ioprio(cprc->f2fs_issue_ckpt, cprc->ckpt_thread_ioprio);

	return 0;
}

// 停止CP任务
void f2fs_stop_ckpt_thread(struct f2fs_sb_info *sbi)
{
	struct ckpt_req_control *cprc = &sbi->cprc_info;
	struct task_struct *ckpt_task;

	if (!cprc->f2fs_issue_ckpt)
		return;

	ckpt_task = cprc->f2fs_issue_ckpt;
	cprc->f2fs_issue_ckpt = NULL;
	kthread_stop(ckpt_task);

	f2fs_flush_ckpt_thread(sbi);
}

// 在本任务下发一次CP操作，在CP任务结束、remount等时机调用
void f2fs_flush_ckpt_thread(struct f2fs_sb_info *sbi)
{
	struct ckpt_req_control *cprc = &sbi->cprc_info;

	// 非通过CP任务的方式下发CP，并将对应的队列设置成完成状态
	flush_remained_ckpt_reqs(sbi, NULL);

	/* Let's wait for the previous dispatched checkpoint. */
	while (atomic_read(&cprc->queued_ckpt))
		io_schedule_timeout(DEFAULT_IO_TIMEOUT);
}

// 初始化CP管理结构体
void f2fs_init_ckpt_req_control(struct f2fs_sb_info *sbi)
{
	struct ckpt_req_control *cprc = &sbi->cprc_info;

	atomic_set(&cprc->issued_ckpt, 0);
	atomic_set(&cprc->total_ckpt, 0);
	atomic_set(&cprc->queued_ckpt, 0);
	cprc->ckpt_thread_ioprio = DEFAULT_CHECKPOINT_IOPRIO;
	init_waitqueue_head(&cprc->ckpt_wait_queue);
	init_llist_head(&cprc->issue_list);
	spin_lock_init(&cprc->stat_lock);
}
