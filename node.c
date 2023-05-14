// SPDX-License-Identifier: GPL-2.0
/*
 * fs/f2fs/node.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include <linux/mpage.h>
#include <linux/sched/mm.h>
#include <linux/blkdev.h>
#include <linux/pagevec.h>
#include <linux/swap.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "xattr.h"
#include "iostat.h"
#include <trace/events/f2fs.h>

#define on_f2fs_build_free_nids(nmi) mutex_is_locked(&(nm_i)->build_lock)

static struct kmem_cache *nat_entry_slab;
static struct kmem_cache *free_nid_slab;
static struct kmem_cache *nat_entry_set_slab;
static struct kmem_cache *fsync_node_entry_slab;

/*
 * Check whether the given nid is within node id range.
 */
int f2fs_check_nid_range(struct f2fs_sb_info *sbi, nid_t nid)
{
	if (unlikely(nid < F2FS_ROOT_INO(sbi) || nid >= NM_I(sbi)->max_nid)) {
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_warn(sbi, "%s: out-of-range nid=%x, run fsck to fix.",
			  __func__, nid);
		f2fs_handle_error(sbi, ERROR_CORRUPTED_INODE);
		return -EFSCORRUPTED;
	}
	return 0;
}

// 检查系统中内存是否充足，这决定是否要清理nat cache
bool f2fs_available_free_memory(struct f2fs_sb_info *sbi, int type)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct sysinfo val;
	unsigned long avail_ram;
	unsigned long mem_size = 0;
	bool res = false;

	if (!nm_i)
		return true;

	si_meminfo(&val);

	/* only uses low memory */
	avail_ram = val.totalram - val.totalhigh;

	/*
	 * give 25%, 25%, 50%, 50%, 25%, 25% memory for each components respectively
	 */
	if (type == FREE_NIDS) {
		mem_size = (nm_i->nid_cnt[FREE_NID] *
				sizeof(struct free_nid)) >> PAGE_SHIFT;
		res = mem_size < ((avail_ram * nm_i->ram_thresh / 100) >> 2);
	} else if (type == NAT_ENTRIES) {
		mem_size = (nm_i->nat_cnt[TOTAL_NAT] *
				sizeof(struct nat_entry)) >> PAGE_SHIFT;
		res = mem_size < ((avail_ram * nm_i->ram_thresh / 100) >> 2);
		if (excess_cached_nats(sbi))
			res = false;
	} else if (type == DIRTY_DENTS) {
		if (sbi->sb->s_bdi->wb.dirty_exceeded)
			return false;
		mem_size = get_pages(sbi, F2FS_DIRTY_DENTS);
		res = mem_size < ((avail_ram * nm_i->ram_thresh / 100) >> 1);
	} else if (type == INO_ENTRIES) {
		int i;

		for (i = 0; i < MAX_INO_ENTRY; i++)
			mem_size += sbi->im[i].ino_num *
						sizeof(struct ino_entry);
		mem_size >>= PAGE_SHIFT;
		res = mem_size < ((avail_ram * nm_i->ram_thresh / 100) >> 1);
	} else if (type == READ_EXTENT_CACHE || type == AGE_EXTENT_CACHE) {
		enum extent_type etype = type == READ_EXTENT_CACHE ?
						EX_READ : EX_BLOCK_AGE;
		struct extent_tree_info *eti = &sbi->extent_tree[etype];

		mem_size = (atomic_read(&eti->total_ext_tree) *
				sizeof(struct extent_tree) +
				atomic_read(&eti->total_ext_node) *
				sizeof(struct extent_node)) >> PAGE_SHIFT;
		res = mem_size < ((avail_ram * nm_i->ram_thresh / 100) >> 2);
	} else if (type == DISCARD_CACHE) {
		mem_size = (atomic_read(&dcc->discard_cmd_cnt) *
				sizeof(struct discard_cmd)) >> PAGE_SHIFT;
		res = mem_size < (avail_ram * nm_i->ram_thresh / 100);
	} else if (type == COMPRESS_PAGE) {
#ifdef CONFIG_F2FS_FS_COMPRESSION
		unsigned long free_ram = val.freeram;

		/*
		 * free memory is lower than watermark or cached page count
		 * exceed threshold, deny caching compress page.
		 */
		res = (free_ram > avail_ram * sbi->compress_watermark / 100) &&
			(COMPRESS_MAPPING(sbi)->nrpages <
			 free_ram * sbi->compress_percent / 100);
#else
		res = false;
#endif
	} else {
		if (!sbi->sb->s_bdi->wb.dirty_exceeded)
			return true;
	}
	return res;
}

// 清理node page的dirty标记，主要是在truncate场景使用
static void clear_node_page_dirty(struct page *page)
{
	if (PageDirty(page)) {
		// 将page从脏链表中摘除
		f2fs_clear_page_cache_dirty_tag(page);
		// 清理bio的dirty标记
		clear_page_dirty_for_io(page);
		// 更新脏node的统计信息
		dec_page_count(F2FS_P_SB(page), F2FS_DIRTY_NODES);
	}
	// 清除uptodate标记，表示缓存中的page不可用，需要从存储介质读取
	ClearPageUptodate(page);
}

// 获取nid对应的nat block页
static struct page *get_current_nat_page(struct f2fs_sb_info *sbi, nid_t nid)
{
	return f2fs_get_meta_page_retry(sbi, current_nat_addr(sbi, nid));
}

// 获取nid对应的nat block，并存放到page cache中（TODO：为什么函数名是next_nat？？？）
static struct page *get_next_nat_page(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct page *src_page;
	struct page *dst_page;
	pgoff_t dst_off;
	void *src_addr;
	void *dst_addr;
	struct f2fs_nm_info *nm_i = NM_I(sbi);

	// 计算nid对应的nat block addr
	dst_off = next_nat_addr(sbi, current_nat_addr(sbi, nid));

	/* get current nat block page with lock */
	// 读取nat block的内容到src_page
	src_page = get_current_nat_page(sbi, nid);
	if (IS_ERR(src_page))
		return src_page;
	// 分配一个page cache，用于存储nat block page。
	dst_page = f2fs_grab_meta_page(sbi, dst_off);
	f2fs_bug_on(sbi, PageDirty(src_page));

	// 将两个page转换成虚拟地址，用于拷贝
	src_addr = page_address(src_page);
	dst_addr = page_address(dst_page);
	memcpy(dst_addr, src_addr, PAGE_SIZE);
	set_page_dirty(dst_page);
	f2fs_put_page(src_page, 1);

	set_to_next_nat(nm_i, nid);

	return dst_page;
}

static struct nat_entry *__alloc_nat_entry(struct f2fs_sb_info *sbi,
						nid_t nid, bool no_fail)
{
	struct nat_entry *new;

	new = f2fs_kmem_cache_alloc(nat_entry_slab,
					GFP_F2FS_ZERO, no_fail, sbi);
	if (new) {
		nat_set_nid(new, nid);
		nat_reset_flag(new);
	}
	return new;
}

static void __free_nat_entry(struct nat_entry *e)
{
	kmem_cache_free(nat_entry_slab, e);
}

/* must be locked by nat_tree_lock */
// 初始化一个nat_entry cache，并放入到nat_root中
static struct nat_entry *__init_nat_entry(struct f2fs_nm_info *nm_i,
	struct nat_entry *ne, struct f2fs_nat_entry *raw_ne, bool no_fail)
{
	if (no_fail)
		f2fs_radix_tree_insert(&nm_i->nat_root, nat_get_nid(ne), ne);
	else if (radix_tree_insert(&nm_i->nat_root, nat_get_nid(ne), ne))
		return NULL;

	if (raw_ne)
		node_info_from_raw_nat(&ne->ni, raw_ne);

	spin_lock(&nm_i->nat_list_lock);
	// 将创建的nat entry放入到nat_entries链表，表示该nat_entry正在被使用。
	list_add_tail(&ne->list, &nm_i->nat_entries);
	spin_unlock(&nm_i->nat_list_lock);

	nm_i->nat_cnt[TOTAL_NAT]++;
	nm_i->nat_cnt[RECLAIMABLE_NAT]++;
	return ne;
}

// 在nat_root中查找一个nat_entry，如果nat_entry是dirty，则将其移动到nat_entries的尾部，
// 为了让其可以更快回收？
static struct nat_entry *__lookup_nat_cache(struct f2fs_nm_info *nm_i, nid_t n)
{
	struct nat_entry *ne;

	ne = radix_tree_lookup(&nm_i->nat_root, n);

	/* for recent accessed nat entry, move it to tail of lru list */
	if (ne && !get_nat_flag(ne, IS_DIRTY)) {
		spin_lock(&nm_i->nat_list_lock);
		if (!list_empty(&ne->list))
			list_move_tail(&ne->list, &nm_i->nat_entries);
		spin_unlock(&nm_i->nat_list_lock);
	}

	return ne;
}

static unsigned int __gang_lookup_nat_cache(struct f2fs_nm_info *nm_i,
		nid_t start, unsigned int nr, struct nat_entry **ep)
{
	return radix_tree_gang_lookup(&nm_i->nat_root, (void **)ep, start, nr);
}

// 删除一个nat_entry
static void __del_from_nat_cache(struct f2fs_nm_info *nm_i, struct nat_entry *e)
{
	radix_tree_delete(&nm_i->nat_root, nat_get_nid(e));
	nm_i->nat_cnt[TOTAL_NAT]--;
	nm_i->nat_cnt[RECLAIMABLE_NAT]--;
	__free_nat_entry(e);
}

// 在nat_set_root查找包含ne的set，用于CP流程
static struct nat_entry_set *__grab_nat_entry_set(struct f2fs_nm_info *nm_i,
							struct nat_entry *ne)
{
	nid_t set = NAT_BLOCK_OFFSET(ne->ni.nid);
	struct nat_entry_set *head;

	head = radix_tree_lookup(&nm_i->nat_set_root, set);
	if (!head) {
		head = f2fs_kmem_cache_alloc(nat_entry_set_slab,
						GFP_NOFS, true, NULL);

		INIT_LIST_HEAD(&head->entry_list);
		INIT_LIST_HEAD(&head->set_list);
		head->set = set;
		head->entry_cnt = 0;
		f2fs_radix_tree_insert(&nm_i->nat_set_root, set, head);
	}
	return head;
}

// 设置一个set里面的nat entry为dirty
static void __set_nat_cache_dirty(struct f2fs_nm_info *nm_i,
						struct nat_entry *ne)
{
	struct nat_entry_set *head;
	bool new_ne = nat_get_blkaddr(ne) == NEW_ADDR;

	if (!new_ne)
		// 根据nat_entry获取到包含该entry的set
		head = __grab_nat_entry_set(nm_i, ne);

	/*
	 * update entry_cnt in below condition:
	 * 1. update NEW_ADDR to valid block address;
	 * 2. update old block address to new one;
	 */
	// 如果该nat entry的blk_addr将要被修改，并且还没有在set中，则
	// set的entry数量加1
	if (!new_ne && (get_nat_flag(ne, IS_PREALLOC) ||
				!get_nat_flag(ne, IS_DIRTY)))
		head->entry_cnt++;

	// 设置nat entry的IS_PREALLOC属性
	set_nat_flag(ne, IS_PREALLOC, new_ne);

	// 获取nat entry的属性，如果page已经是脏页，则无需重新设置，
	// 只需要将nat_entry移动到set的尾部
	if (get_nat_flag(ne, IS_DIRTY))
		goto refresh_list;

	nm_i->nat_cnt[DIRTY_NAT]++;
	nm_i->nat_cnt[RECLAIMABLE_NAT]--;
	set_nat_flag(ne, IS_DIRTY, true);
refresh_list:
	spin_lock(&nm_i->nat_list_lock);
	if (new_ne)
		list_del_init(&ne->list);
	else
		list_move_tail(&ne->list, &head->entry_list);
	spin_unlock(&nm_i->nat_list_lock);
}

// 清理nat_entry的脏属性，需要注意的是，该不从set删除该nat_entry
static void __clear_nat_cache_dirty(struct f2fs_nm_info *nm_i,
		struct nat_entry_set *set, struct nat_entry *ne)
{
	spin_lock(&nm_i->nat_list_lock);
	list_move_tail(&ne->list, &nm_i->nat_entries);
	spin_unlock(&nm_i->nat_list_lock);

	set_nat_flag(ne, IS_DIRTY, false);
	set->entry_cnt--;
	nm_i->nat_cnt[DIRTY_NAT]--;
	nm_i->nat_cnt[RECLAIMABLE_NAT]++;
}

static unsigned int __gang_lookup_nat_set(struct f2fs_nm_info *nm_i,
		nid_t start, unsigned int nr, struct nat_entry_set **ep)
{
	return radix_tree_gang_lookup(&nm_i->nat_set_root, (void **)ep,
							start, nr);
}

bool f2fs_in_warm_node_list(struct f2fs_sb_info *sbi, struct page *page)
{
	return NODE_MAPPING(sbi) == page->mapping &&
			IS_DNODE(page) && is_cold_node(page);
}

void f2fs_init_fsync_node_info(struct f2fs_sb_info *sbi)
{
	spin_lock_init(&sbi->fsync_node_lock);
	INIT_LIST_HEAD(&sbi->fsync_node_list);
	sbi->fsync_seg_id = 0;
	sbi->fsync_node_num = 0;
}

// 将一个提交到bio的page放入到fsync_node_list中，需要注意的是，只处理非hot的direct node page
static unsigned int f2fs_add_fsync_node_entry(struct f2fs_sb_info *sbi,
							struct page *page)
{
	struct fsync_node_entry *fn;
	unsigned long flags;
	unsigned int seq_id;

	fn = f2fs_kmem_cache_alloc(fsync_node_entry_slab,
					GFP_NOFS, true, NULL);

	get_page(page);
	fn->page = page;
	INIT_LIST_HEAD(&fn->list);

	spin_lock_irqsave(&sbi->fsync_node_lock, flags);
	list_add_tail(&fn->list, &sbi->fsync_node_list);
	fn->seq_id = sbi->fsync_seg_id++;
	seq_id = fn->seq_id;
	sbi->fsync_node_num++;
	spin_unlock_irqrestore(&sbi->fsync_node_lock, flags);

	return seq_id;
}

// 从fsync_node_list链表删除一个page，在end_io时触发
void f2fs_del_fsync_node_entry(struct f2fs_sb_info *sbi, struct page *page)
{
	struct fsync_node_entry *fn;
	unsigned long flags;

	spin_lock_irqsave(&sbi->fsync_node_lock, flags);
	list_for_each_entry(fn, &sbi->fsync_node_list, list) {
		if (fn->page == page) {
			list_del(&fn->list);
			sbi->fsync_node_num--;
			spin_unlock_irqrestore(&sbi->fsync_node_lock, flags);
			kmem_cache_free(fsync_node_entry_slab, fn);
			put_page(page);
			return;
		}
	}
	spin_unlock_irqrestore(&sbi->fsync_node_lock, flags);
	f2fs_bug_on(sbi, 1);
}

void f2fs_reset_fsync_node_info(struct f2fs_sb_info *sbi)
{
	unsigned long flags;

	spin_lock_irqsave(&sbi->fsync_node_lock, flags);
	sbi->fsync_seg_id = 0;
	spin_unlock_irqrestore(&sbi->fsync_node_lock, flags);
}

int f2fs_need_dentry_mark(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *e;
	bool need = false;

	f2fs_down_read(&nm_i->nat_tree_lock);
	e = __lookup_nat_cache(nm_i, nid);
	if (e) {
		if (!get_nat_flag(e, IS_CHECKPOINTED) &&
				!get_nat_flag(e, HAS_FSYNCED_INODE))
			need = true;
	}
	f2fs_up_read(&nm_i->nat_tree_lock);
	return need;
}

bool f2fs_is_checkpointed_node(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *e;
	bool is_cp = true;

	f2fs_down_read(&nm_i->nat_tree_lock);
	e = __lookup_nat_cache(nm_i, nid);
	if (e && !get_nat_flag(e, IS_CHECKPOINTED))
		is_cp = false;
	f2fs_up_read(&nm_i->nat_tree_lock);
	return is_cp;
}

bool f2fs_need_inode_block_update(struct f2fs_sb_info *sbi, nid_t ino)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *e;
	bool need_update = true;

	f2fs_down_read(&nm_i->nat_tree_lock);
	e = __lookup_nat_cache(nm_i, ino);
	if (e && get_nat_flag(e, HAS_LAST_FSYNC) &&
			(get_nat_flag(e, IS_CHECKPOINTED) ||
			 get_nat_flag(e, HAS_FSYNCED_INODE)))
		need_update = false;
	f2fs_up_read(&nm_i->nat_tree_lock);
	return need_update;
}

/* must be locked by nat_tree_lock */
// 缓存一个nat_entry到root_nat中
static void cache_nat_entry(struct f2fs_sb_info *sbi, nid_t nid,
						struct f2fs_nat_entry *ne)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *new, *e;

	/* Let's mitigate lock contention of nat_tree_lock during checkpoint */
	if (f2fs_rwsem_is_locked(&sbi->cp_global_sem))
		return;

	new = __alloc_nat_entry(sbi, nid, false);
	if (!new)
		return;

	f2fs_down_write(&nm_i->nat_tree_lock);
	e = __lookup_nat_cache(nm_i, nid);
	if (!e)
		e = __init_nat_entry(nm_i, new, ne, false);
	else
		f2fs_bug_on(sbi, nat_get_ino(e) != le32_to_cpu(ne->ino) ||
				nat_get_blkaddr(e) !=
					le32_to_cpu(ne->block_addr) ||
				nat_get_version(e) != ne->version);
	f2fs_up_write(&nm_i->nat_tree_lock);
	if (e != new)
		__free_nat_entry(new);
}

// 设置一个node的新地址，一般用于异地更新
static void set_node_addr(struct f2fs_sb_info *sbi, struct node_info *ni,
			block_t new_blkaddr, bool fsync_done)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *e;
	struct nat_entry *new = __alloc_nat_entry(sbi, ni->nid, true);

	f2fs_down_write(&nm_i->nat_tree_lock);
	// 查找nid对应的nat entry
	e = __lookup_nat_cache(nm_i, ni->nid);
	if (!e) {
		// 如果root_nat中还没有缓存，则向申请一个，并放入到root_nat中
		e = __init_nat_entry(nm_i, new, NULL, true);
		// 将node的管理信息拷贝到缓存中
		copy_node_info(&e->ni, ni);
		f2fs_bug_on(sbi, ni->blk_addr == NEW_ADDR);
	} else if (new_blkaddr == NEW_ADDR) {
		/*
		 * when nid is reallocated,
		 * previous nat entry can be remained in nat cache.
		 * So, reinitialize it with new information.
		 */
		// 如果root_nat中已经缓存在nat_netry，并且本次是设置NEW_ADDR（预留一个block），
		// 则只需要拷贝到缓存
		copy_node_info(&e->ni, ni);
		f2fs_bug_on(sbi, ni->blk_addr != NULL_ADDR);
	}
	/* let's free early to reduce memory consumption */
	// 如果新创建的nat_entry没有被使用，则直接删除
	if (e != new)
		__free_nat_entry(new);

	/* sanity check */
	f2fs_bug_on(sbi, nat_get_blkaddr(e) != ni->blk_addr);
	f2fs_bug_on(sbi, nat_get_blkaddr(e) == NULL_ADDR &&
			new_blkaddr == NULL_ADDR);
	f2fs_bug_on(sbi, nat_get_blkaddr(e) == NEW_ADDR &&
			new_blkaddr == NEW_ADDR);
	f2fs_bug_on(sbi, __is_valid_data_blkaddr(nat_get_blkaddr(e)) &&
			new_blkaddr == NEW_ADDR);

	/* increment version no as node is removed */
	if (nat_get_blkaddr(e) != NEW_ADDR && new_blkaddr == NULL_ADDR) {
		unsigned char version = nat_get_version(e);

		nat_set_version(e, inc_node_version(version));
	}

	/* change address */
	// 设置node的新地址
	nat_set_blkaddr(e, new_blkaddr);
	// 如果new_blkaddr是某个block的地址，则需要置上IS_CHECKPOINTED标记
	if (!__is_valid_data_blkaddr(new_blkaddr))
		set_nat_flag(e, IS_CHECKPOINTED, false);
	// 设置nat_entry缓存的dirty标记
	__set_nat_cache_dirty(nm_i, e);

	/* update fsync_mark if its inode nat entry is still alive */
	// TODO：
	if (ni->nid != ni->ino)
		e = __lookup_nat_cache(nm_i, ni->ino);
	if (e) {
		if (fsync_done && ni->nid == ni->ino)
			set_nat_flag(e, HAS_FSYNCED_INODE, true);
		set_nat_flag(e, HAS_LAST_FSYNC, fsync_done);
	}
	f2fs_up_write(&nm_i->nat_tree_lock);
}

// 释放nr_shrink个nat entry缓存
int f2fs_try_to_free_nats(struct f2fs_sb_info *sbi, int nr_shrink)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	int nr = nr_shrink;

	if (!f2fs_down_write_trylock(&nm_i->nat_tree_lock))
		return 0;

	spin_lock(&nm_i->nat_list_lock);
	while (nr_shrink) {
		struct nat_entry *ne;

		if (list_empty(&nm_i->nat_entries))
			break;

		ne = list_first_entry(&nm_i->nat_entries,
					struct nat_entry, list);
		list_del(&ne->list);
		spin_unlock(&nm_i->nat_list_lock);

		__del_from_nat_cache(nm_i, ne);
		nr_shrink--;

		spin_lock(&nm_i->nat_list_lock);
	}
	spin_unlock(&nm_i->nat_list_lock);

	f2fs_up_write(&nm_i->nat_tree_lock);
	return nr - nr_shrink;
}

// 获取node的管理信息
int f2fs_get_node_info(struct f2fs_sb_info *sbi, nid_t nid,
				struct node_info *ni, bool checkpoint_context)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	struct f2fs_journal *journal = curseg->journal;
	nid_t start_nid = START_NID(nid);
	struct f2fs_nat_block *nat_blk;
	struct page *page = NULL;
	struct f2fs_nat_entry ne;
	struct nat_entry *e;
	pgoff_t index;
	block_t blkaddr;
	int i;

	ni->nid = nid;
retry:
	/* Check nat cache */
	// 优先从nat_root中获取，这里缓存着node的管理信息
	f2fs_down_read(&nm_i->nat_tree_lock);
	e = __lookup_nat_cache(nm_i, nid);
	if (e) {
		ni->ino = nat_get_ino(e);
		ni->blk_addr = nat_get_blkaddr(e);
		ni->version = nat_get_version(e);
		f2fs_up_read(&nm_i->nat_tree_lock);
		return 0;
	}

	/*
	 * Check current segment summary by trying to grab journal_rwsem first.
	 * This sem is on the critical path on the checkpoint requiring the above
	 * nat_tree_lock. Therefore, we should retry, if we failed to grab here
	 * while not bothering checkpoint.
	 */
	if (!f2fs_rwsem_is_locked(&sbi->cp_global_sem) || checkpoint_context) {
		down_read(&curseg->journal_rwsem);
	} else if (f2fs_rwsem_is_contended(&nm_i->nat_tree_lock) ||
				!down_read_trylock(&curseg->journal_rwsem)) {
		f2fs_up_read(&nm_i->nat_tree_lock);
		goto retry;
	}

	// 如果nat_root中没有缓存该node，则在journal中查找
	i = f2fs_lookup_journal_in_cursum(journal, NAT_JOURNAL, nid, 0);
	if (i >= 0) {
		ne = nat_in_journal(journal, i);
		node_info_from_raw_nat(ni, &ne);
	}
	up_read(&curseg->journal_rwsem);
	if (i >= 0) {
		f2fs_up_read(&nm_i->nat_tree_lock);
		// 在journal中找到缓存，但nat_root中没有，则需要放入到nat_root
		goto cache;
	}

	/* Fill node_info from nat page */
	// 如果journal中也没有，那只能从NAT区域中获取了
	index = current_nat_addr(sbi, nid);
	f2fs_up_read(&nm_i->nat_tree_lock);

	page = f2fs_get_meta_page(sbi, index);
	if (IS_ERR(page))
		return PTR_ERR(page);

	nat_blk = (struct f2fs_nat_block *)page_address(page);
	ne = nat_blk->entries[nid - start_nid];
	node_info_from_raw_nat(ni, &ne);
	f2fs_put_page(page, 1);
cache:
	blkaddr = le32_to_cpu(ne.block_addr);
	if (__is_valid_data_blkaddr(blkaddr) &&
		!f2fs_is_valid_blkaddr(sbi, blkaddr, DATA_GENERIC_ENHANCE))
		return -EFAULT;

	/* cache nat entry */
	// 放入nat_root缓存，加快后续的查找
	cache_nat_entry(sbi, nid, &ne);
	return 0;
}

/*
 * readahead MAX_RA_NODE number of node pages.
 */
static void f2fs_ra_node_pages(struct page *parent, int start, int n)
{
	struct f2fs_sb_info *sbi = F2FS_P_SB(parent);
	struct blk_plug plug;
	int i, end;
	nid_t nid;

	blk_start_plug(&plug);

	/* Then, try readahead for siblings of the desired node */
	end = start + n;
	end = min(end, NIDS_PER_BLOCK);
	for (i = start; i < end; i++) {
		nid = get_nid(parent, i, false);
		f2fs_ra_node_page(sbi, nid);
	}

	blk_finish_plug(&plug);
}

pgoff_t f2fs_get_next_page_offset(struct dnode_of_data *dn, pgoff_t pgofs)
{
	const long direct_index = ADDRS_PER_INODE(dn->inode);
	const long direct_blks = ADDRS_PER_BLOCK(dn->inode);
	const long indirect_blks = ADDRS_PER_BLOCK(dn->inode) * NIDS_PER_BLOCK;
	unsigned int skipped_unit = ADDRS_PER_BLOCK(dn->inode);
	int cur_level = dn->cur_level;
	int max_level = dn->max_level;
	pgoff_t base = 0;

	if (!dn->max_level)
		return pgofs + 1;

	while (max_level-- > cur_level)
		skipped_unit *= NIDS_PER_BLOCK;

	switch (dn->max_level) {
	case 3:
		base += 2 * indirect_blks;
		fallthrough;
	case 2:
		base += 2 * direct_blks;
		fallthrough;
	case 1:
		base += direct_index;
		break;
	default:
		f2fs_bug_on(F2FS_I_SB(dn->inode), 1);
	}

	return ((pgofs - base) / skipped_unit + 1) * skipped_unit + base;
}

/*
 * The maximum depth is four.
 * Offset[0] will have raw inode offset.
 */
// 获取node的逻辑地址，其中noffst记录的是逻辑node号，offset记录的是每个逻辑node号的偏移
// 例如：如果一个node在dindirect中，则noffset[3]记录的是直接索引该node block的indirect block，
// 而offset[3]则是在该indirect block的下标
static int get_node_path(struct inode *inode, long block,
				int offset[4], unsigned int noffset[4])
{
	const long direct_index = ADDRS_PER_INODE(inode);
	const long direct_blks = ADDRS_PER_BLOCK(inode);
	const long dptrs_per_blk = NIDS_PER_BLOCK;
	const long indirect_blks = ADDRS_PER_BLOCK(inode) * NIDS_PER_BLOCK;
	const long dindirect_blks = indirect_blks * NIDS_PER_BLOCK;
	int n = 0;
	int level = 0;

	// 第0层是inode，其逻辑index号是0
	noffset[0] = 0;

	if (block < direct_index) {
		offset[n] = block;
		goto got;
	}
	block -= direct_index;
	if (block < direct_blks) {
		// 第1层是第一个direct node，其逻辑编号是1
		offset[n++] = NODE_DIR1_BLOCK;
		noffset[n] = 1;
		offset[n] = block;
		level = 1;
		goto got;
	}
	block -= direct_blks;
	if (block < direct_blks) {
		// 另一个第1层是第二个direct node，其逻辑编号是2
		offset[n++] = NODE_DIR2_BLOCK;
		noffset[n] = 2;
		offset[n] = block;
		level = 1;
		goto got;
	}
	block -= direct_blks;
	if (block < indirect_blks) {
		// 第2层是第1个indirect node，其逻辑编号是3
		offset[n++] = NODE_IND1_BLOCK;
		noffset[n] = 3;
		offset[n++] = block / direct_blks;
		noffset[n] = 4 + offset[n - 1];
		offset[n] = block % direct_blks;
		level = 2;
		goto got;
	}
	block -= indirect_blks;
	if (block < indirect_blks) {
		offset[n++] = NODE_IND2_BLOCK;
		noffset[n] = 4 + dptrs_per_blk;
		offset[n++] = block / direct_blks;
		noffset[n] = 5 + dptrs_per_blk + offset[n - 1];
		offset[n] = block % direct_blks;
		level = 2;
		goto got;
	}
	block -= indirect_blks;
	if (block < dindirect_blks) {
		offset[n++] = NODE_DIND_BLOCK;
		noffset[n] = 5 + (dptrs_per_blk * 2);
		offset[n++] = block / indirect_blks;
		noffset[n] = 6 + (dptrs_per_blk * 2) +
			      offset[n - 1] * (dptrs_per_blk + 1);
		offset[n++] = (block / direct_blks) % dptrs_per_blk;
		noffset[n] = 7 + (dptrs_per_blk * 2) +
			      offset[n - 2] * (dptrs_per_blk + 1) +
			      offset[n - 1];
		offset[n] = block % direct_blks;
		level = 3;
		goto got;
	} else {
		return -E2BIG;
	}
got:
	return level;
}

/*
 * Caller should call f2fs_put_dnode(dn).
 * Also, it should grab and release a rwsem by calling f2fs_lock_op() and
 * f2fs_unlock_op() only if mode is set with ALLOC_NODE.
 */
// 获取一个逻辑编号为index的node信息，包括其对应的inode page，直接索引其的page
int f2fs_get_dnode_of_data(struct dnode_of_data *dn, pgoff_t index, int mode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);
	struct page *npage[4];
	struct page *parent = NULL;
	int offset[4];
	unsigned int noffset[4];
	nid_t nids[4];
	int level, i = 0;
	int err = 0;

	// 根据index的逻辑地址，获取每一层的信息，通过noffset + offset可以找到这个node block
	level = get_node_path(dn->inode, index, offset, noffset);
	if (level < 0)
		return level;

	// nids记录每一层级的node id号，第0层级是inode
	nids[0] = dn->inode->i_ino;
	// npage在记录每一层级的page
	npage[0] = dn->inode_page;

	if (!npage[0]) {
		// 如果inode的page还没在dn中记录，则读取
		npage[0] = f2fs_get_node_page(sbi, nids[0]);
		if (IS_ERR(npage[0]))
			return PTR_ERR(npage[0]);
	}

	/* if inline_data is set, should not report any block indices */
	// 如果该inode有inline数据，则表示其大小不超过4kB，只能有一个层级（inode层级）
	if (f2fs_has_inline_data(dn->inode) && index) {
		err = -ENOENT;
		f2fs_put_page(npage[0], 1);
		goto release_out;
	}

	// 如果是多个层级，则需要遍历读取
	parent = npage[0];
	if (level != 0)
		nids[1] = get_nid(parent, offset[0], true);
	dn->inode_page = npage[0];
	dn->inode_page_locked = true;

	/* get indirect or direct nodes */
	for (i = 1; i <= level; i++) {
		bool done = false;

		// 如果某一层级的node block不存在，并且是ALLOC_NODE模式，需要申请一个新的node
		if (!nids[i] && mode == ALLOC_NODE) {
			/* alloc new node */
			if (!f2fs_alloc_nid(sbi, &(nids[i]))) {
				err = -ENOSPC;
				goto release_pages;
			}

			dn->nid = nids[i];
			npage[i] = f2fs_new_node_page(dn, noffset[i]);
			if (IS_ERR(npage[i])) {
				f2fs_alloc_nid_failed(sbi, nids[i]);
				err = PTR_ERR(npage[i]);
				goto release_pages;
			}

			set_nid(parent, offset[i - 1], nids[i], i == 1);
			f2fs_alloc_nid_done(sbi, nids[i]);
			done = true;
		} else if (mode == LOOKUP_NODE_RA && i == level && level > 1) {
			// 读取用于索引node的page到npage
			npage[i] = f2fs_get_node_page_ra(parent, offset[i - 1]);
			if (IS_ERR(npage[i])) {
				err = PTR_ERR(npage[i]);
				goto release_pages;
			}
			done = true;
		}
		if (i == 1) {
			dn->inode_page_locked = false;
			unlock_page(parent);
		} else {
			f2fs_put_page(parent, 1);
		}

		if (!done) {
			npage[i] = f2fs_get_node_page(sbi, nids[i]);
			if (IS_ERR(npage[i])) {
				err = PTR_ERR(npage[i]);
				f2fs_put_page(npage[0], 0);
				goto release_out;
			}
		}
		if (i < level) {
			parent = npage[i];
			nids[i + 1] = get_nid(parent, offset[i], false);
		}
	}
	dn->nid = nids[level];
	dn->ofs_in_node = offset[level];
	dn->node_page = npage[level];
	dn->data_blkaddr = f2fs_data_blkaddr(dn);

	// TODO：压缩文件相关
	if (is_inode_flag_set(dn->inode, FI_COMPRESSED_FILE) &&
					f2fs_sb_has_readonly(sbi)) {
		unsigned int c_len = f2fs_cluster_blocks_are_contiguous(dn);
		block_t blkaddr;

		if (!c_len)
			goto out;

		blkaddr = f2fs_data_blkaddr(dn);
		if (blkaddr == COMPRESS_ADDR)
			blkaddr = data_blkaddr(dn->inode, dn->node_page,
						dn->ofs_in_node + 1);

		f2fs_update_read_extent_tree_range_compressed(dn->inode,
					index, blkaddr,
					F2FS_I(dn->inode)->i_cluster_size,
					c_len);
	}
out:
	return 0;

release_pages:
	f2fs_put_page(parent, 1);
	if (i > 1)
		f2fs_put_page(npage[0], 0);
release_out:
	dn->inode_page = NULL;
	dn->node_page = NULL;
	if (err == -ENOENT) {
		dn->cur_level = i;
		dn->max_level = level;
		dn->ofs_in_node = offset[level];
	}
	return err;
}

// 裁剪一个node block
static int truncate_node(struct dnode_of_data *dn)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);
	struct node_info ni;
	int err;
	pgoff_t index;

	// 获取node block的管理信息
	err = f2fs_get_node_info(sbi, dn->nid, &ni, false);
	if (err)
		return err;

	/* Deallocate node address */
	// 在segment中将direct node置为无效
	f2fs_invalidate_blocks(sbi, ni.blk_addr);
	// 调整total_valid_block_count和total_valid_node_count的统计信息
	dec_valid_node_count(sbi, dn->inode, dn->nid == dn->inode->i_ino);
	// 将该node block的blk_addr置为NULL_ADDR，表示该node block不可用，等待GC任务回收
	set_node_addr(sbi, &ni, NULL_ADDR, false);

	// 如果该node是inode，删除对应的orphan node，则还需要调整inode的统计信息
	if (dn->nid == dn->inode->i_ino) {
		f2fs_remove_orphan_inode(sbi, dn->nid);
		dec_valid_inode_count(sbi);
		f2fs_inode_synced(dn->inode);
	}

	// 清除node block的dirty标记
	clear_node_page_dirty(dn->node_page);
	set_sbi_flag(sbi, SBI_IS_DIRTY);

	index = dn->node_page->index;
	f2fs_put_page(dn->node_page, 1);

	// 删除page cache中对应的index
	invalidate_mapping_pages(NODE_MAPPING(sbi),
			index, index);

	dn->node_page = NULL;
	trace_f2fs_truncate_node(dn->inode, dn->nid, ni.blk_addr);

	return 0;
}

// 裁剪一个direct node
static int truncate_dnode(struct dnode_of_data *dn)
{
	struct page *page;
	int err;

	// 如果是inode，则不处理（有）
	if (dn->nid == 0)
		return 1;

	/* get direct node */
	page = f2fs_get_node_page(F2FS_I_SB(dn->inode), dn->nid);
	if (PTR_ERR(page) == -ENOENT)
		return 1;
	else if (IS_ERR(page))
		return PTR_ERR(page);

	/* Make dnode_of_data for parameter */
	dn->node_page = page;
	// 由于这是一个direct node，所以ofs_in_node是0（只有data block才需要使用该成员）
	dn->ofs_in_node = 0;
	// 将挂在该direct node下的所有data block裁剪掉
	f2fs_truncate_data_blocks(dn);
	// 裁剪该direct node
	err = truncate_node(dn);
	if (err)
		return err;

	return 1;
}

// 裁剪多个node block，包括direct node和indirect node
static int truncate_nodes(struct dnode_of_data *dn, unsigned int nofs,
						int ofs, int depth)
{
	struct dnode_of_data rdn = *dn;
	struct page *page;
	struct f2fs_node *rn;
	nid_t child_nid;
	unsigned int child_nofs;
	int freed = 0;
	int i, ret;

	if (dn->nid == 0)
		return NIDS_PER_BLOCK + 1;

	trace_f2fs_truncate_nodes_enter(dn->inode, dn->nid, dn->data_blkaddr);

	// 获取待裁剪的node page
	page = f2fs_get_node_page(F2FS_I_SB(dn->inode), dn->nid);
	if (IS_ERR(page)) {
		trace_f2fs_truncate_nodes_exit(dn->inode, PTR_ERR(page));
		return PTR_ERR(page);
	}

	// 预读挂在该node block下的data block或者node block
	f2fs_ra_node_pages(page, ofs, NIDS_PER_BLOCK);

	rn = F2FS_NODE(page);
	// 非dindirect node场景，遍历一个indirect node，将其所有
	// direct node裁剪
	if (depth < 3) {
		for (i = ofs; i < NIDS_PER_BLOCK; i++, freed++) {
			// 获取子direct node的id号
			child_nid = le32_to_cpu(rn->in.nid[i]);
			if (child_nid == 0)
				continue;
			rdn.nid = child_nid;
			// 裁剪direct node
			ret = truncate_dnode(&rdn);
			if (ret < 0)
				goto out_err;
			if (set_nid(page, i, 0, false))
				dn->node_changed = true;
		}
	} else {
		// 如果是dindirect node，则通过递归的方式裁剪
		child_nofs = nofs + ofs * (NIDS_PER_BLOCK + 1) + 1;
		for (i = ofs; i < NIDS_PER_BLOCK; i++) {
			// 获取子indirect node的id号
			child_nid = le32_to_cpu(rn->in.nid[i]);
			if (child_nid == 0) {
				// 指向下一个indirect node的逻辑号
				child_nofs += NIDS_PER_BLOCK + 1;
				continue;
			}
			rdn.nid = child_nid;
			// 裁剪一个indirect node
			ret = truncate_nodes(&rdn, child_nofs, 0, depth - 1);
			if (ret == (NIDS_PER_BLOCK + 1)) {
				if (set_nid(page, i, 0, false))
					dn->node_changed = true;
				child_nofs += ret;
			} else if (ret < 0 && ret != -ENOENT) {
				goto out_err;
			}
		}
		freed = child_nofs;
	}

	// 如果是裁剪整个indirect node，则同时将indirect node本身的page也裁剪掉
	if (!ofs) {
		/* remove current indirect node */
		dn->node_page = page;
		ret = truncate_node(dn);
		if (ret)
			goto out_err;
		freed++;
	} else {
		f2fs_put_page(page, 1);
	}
	trace_f2fs_truncate_nodes_exit(dn->inode, freed);
	return freed;

out_err:
	f2fs_put_page(page, 1);
	trace_f2fs_truncate_nodes_exit(dn->inode, ret);
	return ret;
}

// 裁剪一个indirect node的部分项（即部分direct node），这里是为了对齐，
// 先把部分的项裁剪掉，剩下的都是整块裁剪
static int truncate_partial_nodes(struct dnode_of_data *dn,
			struct f2fs_inode *ri, int *offset, int depth)
{
	struct page *pages[2];
	nid_t nid[3];
	nid_t child_nid;
	int err = 0;
	int i;
	int idx = depth - 2;

	// 获取第0级的指针（也即存储在inode中的指针）
	nid[0] = le32_to_cpu(ri->i_nid[offset[0] - NODE_DIR1_BLOCK]);
	if (!nid[0])
		return 0;

	/* get indirect nodes in the path */
	for (i = 0; i < idx + 1; i++) {
		/* reference count'll be increased */
		// 获取indirect node page
		pages[i] = f2fs_get_node_page(F2FS_I_SB(dn->inode), nid[i]);
		if (IS_ERR(pages[i])) {
			err = PTR_ERR(pages[i]);
			idx = i - 1;
			goto fail;
		}
		nid[i + 1] = get_nid(pages[i], offset[i + 1], false);
	}

	// 预读最后一个层级的indirect node的所有项（即direct node）
	f2fs_ra_node_pages(pages[idx], offset[idx + 1], NIDS_PER_BLOCK);

	/* free direct nodes linked to a partial indirect node */
	// 将挂在indirect node下的direct node裁剪掉
	for (i = offset[idx + 1]; i < NIDS_PER_BLOCK; i++) {
		child_nid = get_nid(pages[idx], i, false);
		if (!child_nid)
			continue;
		dn->nid = child_nid;
		err = truncate_dnode(dn);
		if (err < 0)
			goto fail;
		if (set_nid(pages[idx], i, 0, false))
			dn->node_changed = true;
	}

	// 如果indirect node已经为空，同样将其裁剪掉
	if (offset[idx + 1] == 0) {
		dn->node_page = pages[idx];
		dn->nid = nid[idx];
		err = truncate_node(dn);
		if (err)
			goto fail;
	} else {
		f2fs_put_page(pages[idx], 1);
	}
	// 由于部分的项已经清理，所以这里要指向下一个层级的项
	offset[idx]++;
	// 本层级的部分direct node已经处理完成
	offset[idx + 1] = 0;
	idx--;
fail:
	for (i = idx; i >= 0; i--)
		f2fs_put_page(pages[i], 1);

	trace_f2fs_truncate_partial_nodes(dn->inode, nid, depth, err);

	return err;
}

/*
 * All the block addresses of data and nodes should be nullified.
 */
// 从逻辑号为from的node开始到文件的最后，都会被裁剪
int f2fs_truncate_inode_blocks(struct inode *inode, pgoff_t from)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int err = 0, cont = 1;
	int level, offset[4], noffset[4];
	unsigned int nofs = 0;
	struct f2fs_inode *ri;
	struct dnode_of_data dn;
	struct page *page;

	trace_f2fs_truncate_inode_blocks_enter(inode, from);

	// 获取from逻辑号的位置（noffset记录的是每一层级的node逻辑号，offset则是在该页中的偏移）
	// 例如：noffset[level] + offset[level]则是最终的索引项
	level = get_node_path(inode, from, offset, noffset);
	if (level < 0) {
		trace_f2fs_truncate_inode_blocks_exit(inode, level);
		return level;
	}

	// 获取对应inode的page
	page = f2fs_get_node_page(sbi, inode->i_ino);
	if (IS_ERR(page)) {
		trace_f2fs_truncate_inode_blocks_exit(inode, PTR_ERR(page));
		return PTR_ERR(page);
	}

	set_new_dnode(&dn, inode, page, NULL, 0);
	unlock_page(page);

	ri = F2FS_INODE(page);
	switch (level) {
	case 0:
	case 1:
		// 如果层级少于2,则不需要处理indirect node的情况
		nofs = noffset[1];
		break;
	case 2:
		// 需要处理indirect node的情况，首先处理部分indirect node
		// nofs表示处理整个（下面的处理流程）node page时的逻辑node号
		nofs = noffset[1];
		if (!offset[level - 1])
			goto skip_partial;
		err = truncate_partial_nodes(&dn, ri, offset, level);
		if (err < 0 && err != -ENOENT)
			goto fail;
		// 由于部分indirect node已经被处理了，所以要调整下一次需要处理
		// 的逻辑node号
		nofs += 1 + NIDS_PER_BLOCK;
		break;
	case 3:
		nofs = 5 + 2 * NIDS_PER_BLOCK;
		if (!offset[level - 1])
			goto skip_partial;
		err = truncate_partial_nodes(&dn, ri, offset, level);
		if (err < 0 && err != -ENOENT)
			goto fail;
		break;
	default:
		BUG();
	}

skip_partial:
	while (cont) {
		dn.nid = le32_to_cpu(ri->i_nid[offset[0] - NODE_DIR1_BLOCK]);
		switch (offset[0]) {
		case NODE_DIR1_BLOCK:
		case NODE_DIR2_BLOCK:
			err = truncate_dnode(&dn);
			break;

		// 处理indirect node
		case NODE_IND1_BLOCK:
		case NODE_IND2_BLOCK:
			err = truncate_nodes(&dn, nofs, offset[1], 2);
			break;

		case NODE_DIND_BLOCK:
			err = truncate_nodes(&dn, nofs, offset[1], 3);
			cont = 0;
			break;

		default:
			BUG();
		}
		if (err < 0 && err != -ENOENT)
			goto fail;
		// 第1级的node已经被裁剪了，要把对应的父项清零
		if (offset[1] == 0 &&
				ri->i_nid[offset[0] - NODE_DIR1_BLOCK]) {
			lock_page(page);
			BUG_ON(page->mapping != NODE_MAPPING(sbi));
			f2fs_wait_on_page_writeback(page, NODE, true, true);
			ri->i_nid[offset[0] - NODE_DIR1_BLOCK] = 0;
			set_page_dirty(page);
			unlock_page(page);
		}
		offset[1] = 0;
		offset[0]++;
		nofs += err;
	}
fail:
	f2fs_put_page(page, 0);
	trace_f2fs_truncate_inode_blocks_exit(inode, err);
	return err > 0 ? 0 : err;
}

/* caller must lock inode page */
// 裁剪一个xattr node
int f2fs_truncate_xattr_node(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	nid_t nid = F2FS_I(inode)->i_xattr_nid;
	struct dnode_of_data dn;
	struct page *npage;
	int err;

	if (!nid)
		return 0;

	npage = f2fs_get_node_page(sbi, nid);
	if (IS_ERR(npage))
		return PTR_ERR(npage);

	set_new_dnode(&dn, inode, NULL, npage, nid);
	err = truncate_node(&dn);
	if (err) {
		f2fs_put_page(npage, 1);
		return err;
	}

	// 将xattr的node id号清零
	f2fs_i_xnid_write(inode, 0);

	return 0;
}

/*
 * Caller should grab and release a rwsem by calling f2fs_lock_op() and
 * f2fs_unlock_op().
 */
// 移除一个inode
int f2fs_remove_inode_page(struct inode *inode)
{
	struct dnode_of_data dn;
	int err;

	set_new_dnode(&dn, inode, NULL, NULL, inode->i_ino);
	err = f2fs_get_dnode_of_data(&dn, 0, LOOKUP_NODE);
	if (err)
		return err;

	// 如果inode有xattr数据，则先清理
	err = f2fs_truncate_xattr_node(inode);
	if (err) {
		f2fs_put_dnode(&dn);
		return err;
	}

	/* remove potential inline_data blocks */
	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
				S_ISLNK(inode->i_mode))
		f2fs_truncate_data_blocks_range(&dn, 1);

	/* 0 is possible, after f2fs_new_inode() has failed */
	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode)))) {
		f2fs_put_dnode(&dn);
		return -EIO;
	}

	if (unlikely(inode->i_blocks != 0 && inode->i_blocks != 8)) {
		f2fs_warn(F2FS_I_SB(inode),
			"f2fs_remove_inode_page: inconsistent i_blocks, ino:%lu, iblocks:%llu",
			inode->i_ino, (unsigned long long)inode->i_blocks);
		set_sbi_flag(F2FS_I_SB(inode), SBI_NEED_FSCK);
	}

	/* will put inode & node pages */
	err = truncate_node(&dn);
	if (err) {
		f2fs_put_dnode(&dn);
		return err;
	}
	return 0;
}

// 创建一个新的inode block页
struct page *f2fs_new_inode_page(struct inode *inode)
{
	struct dnode_of_data dn;

	/* allocate inode page for new inode */
	set_new_dnode(&dn, inode, NULL, NULL, inode->i_ino);

	/* caller should f2fs_put_page(page, 1); */
	return f2fs_new_node_page(&dn, 0);
}

// 创建一个新的node page（在f2fs_alloc_nid分配完nid后调用？）
// 这里应该没有实际分配block addr，只分配page cache，等待真正需要关联block的时候再分配
struct page *f2fs_new_node_page(struct dnode_of_data *dn, unsigned int ofs)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);
	struct node_info new_ni;
	struct page *page;
	int err;

	if (unlikely(is_inode_flag_set(dn->inode, FI_NO_ALLOC)))
		return ERR_PTR(-EPERM);

	// 获取page cache，如果不存在，则分配一个
	page = f2fs_grab_cache_page(NODE_MAPPING(sbi), dn->nid, false);
	if (!page)
		return ERR_PTR(-ENOMEM);

	if (unlikely((err = inc_valid_node_count(sbi, dn->inode, !ofs))))
		goto fail;

#ifdef CONFIG_F2FS_CHECK_FS
	err = f2fs_get_node_info(sbi, dn->nid, &new_ni, false);
	if (err) {
		dec_valid_node_count(sbi, dn->inode, !ofs);
		goto fail;
	}
	if (unlikely(new_ni.blk_addr != NULL_ADDR)) {
		err = -EFSCORRUPTED;
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_handle_error(sbi, ERROR_INVALID_BLKADDR);
		goto fail;
	}
#endif
	new_ni.nid = dn->nid;
	new_ni.ino = dn->inode->i_ino;
	new_ni.blk_addr = NULL_ADDR;
	new_ni.flag = 0;
	new_ni.version = 0;
	// 设置node的blk_addr为NEW_ADDR，表示预留地址，后续真正使用才分配。
	set_node_addr(sbi, &new_ni, NEW_ADDR, false);

	// 可能page正在被其他任务使用，所以需要等待回写完成。
	f2fs_wait_on_page_writeback(page, NODE, true, true);
	// 填充node的管理信息
	fill_node_footer(page, dn->nid, dn->inode->i_ino, ofs, true);
	// 如果是目录（dentry）类型，则是HOT_NODE，其他都是COLD_NODE类型，用于GC场景。
	set_cold_node(page, S_ISDIR(dn->inode->i_mode));
	if (!PageUptodate(page))
		SetPageUptodate(page);
	if (set_page_dirty(page))
		dn->node_changed = true;

	// 如果申请的node page用作xattr block，则需要将对应的node id号填写到i_xattr_nid
	if (f2fs_has_xattr_block(ofs))
		f2fs_i_xnid_write(dn->inode, dn->nid);

	// 一个node的ofs是0,表示这是一个inode，还需要更新统计信息。
	if (ofs == 0)
		inc_valid_inode_count(sbi);
	return page;

fail:
	clear_node_page_dirty(page);
	f2fs_put_page(page, 1);
	return ERR_PTR(err);
}

/*
 * Caller should do after getting the following values.
 * 0: f2fs_put_page(page, 0)
 * LOCKED_PAGE or error: f2fs_put_page(page, 1)
 */
static int read_node_page(struct page *page, blk_opf_t op_flags)
{
	struct f2fs_sb_info *sbi = F2FS_P_SB(page);
	struct node_info ni;
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.type = NODE,
		.op = REQ_OP_READ,
		.op_flags = op_flags,
		.page = page,
		.encrypted_page = NULL,
	};
	int err;

	// page cache中的page可用，则直接返回给上层，需要注意的是，这时候
	// page是已经上锁了的，所以返回结果是LOCKED_PAGE。
	if (PageUptodate(page)) {
		if (!f2fs_inode_chksum_verify(sbi, page)) {
			ClearPageUptodate(page);
			return -EFSBADCRC;
		}
		return LOCKED_PAGE;
	}

	// 首先获取node对应的管理信息
	err = f2fs_get_node_info(sbi, page->index, &ni, false);
	if (err)
		return err;

	/* NEW_ADDR can be seen, after cp_error drops some dirty node pages */
	// 如果node的block地址不合法，则返错。
	if (unlikely(ni.blk_addr == NULL_ADDR || ni.blk_addr == NEW_ADDR)) {
		ClearPageUptodate(page);
		return -ENOENT;
	}

	// 由于是读取操作，无需新分配node block，所以new_blkaddr和old_blkaddr相同。
	fio.new_blkaddr = fio.old_blkaddr = ni.blk_addr;

	// 提交读node page操作的bio。
	err = f2fs_submit_page_bio(&fio);

	if (!err)
		f2fs_update_iostat(sbi, NULL, FS_NODE_READ_IO, F2FS_BLKSIZE);

	return err;
}

/*
 * Readahead a node page
 */
// 预读一个node page
void f2fs_ra_node_page(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct page *apage;
	int err;

	if (!nid)
		return;
	if (f2fs_check_nid_range(sbi, nid))
		return;

	// 先直接从xarray中查找？避免调用f2fs_grab_cache_page，可能该接口
	// 很耗时
	apage = xa_load(&NODE_MAPPING(sbi)->i_pages, nid);
	if (apage)
		return;

	// 如果node page没有在page cache，需要先分配一个，然后异步预读。
	apage = f2fs_grab_cache_page(NODE_MAPPING(sbi), nid, false);
	if (!apage)
		return;

	// 异步预读
	err = read_node_page(apage, REQ_RAHEAD);
	f2fs_put_page(apage, err ? 1 : 0);
}

// 从page cache或者存储介质读取一个node page
static struct page *__get_node_page(struct f2fs_sb_info *sbi, pgoff_t nid,
					struct page *parent, int start)
{
	struct page *page;
	int err;

	if (!nid)
		return ERR_PTR(-ENOENT);
	if (f2fs_check_nid_range(sbi, nid))
		return ERR_PTR(-EINVAL);
repeat:
	// 首先从page cache读取，如果读取到page，则会上锁；
	// 如果读取不到，则会在mapping分配一个page cache，用于
	// 从存储介质读取，这时候page不上锁
	page = f2fs_grab_cache_page(NODE_MAPPING(sbi), nid, false);
	if (!page)
		return ERR_PTR(-ENOMEM);

	// 获取page的内容，如果page cache已经缓存该page，并且可用，则可直接使用（注意：
	// 此时返回的结果是LOCKED_PAGE，因为是在f2fs_grab_cache_page上锁的）。
	// 如果是其他情况，则需要从存储介质中读取，这时候page没有上锁。
	err = read_node_page(page, 0);
	if (err < 0) {
		goto out_put_err;
	} else if (err == LOCKED_PAGE) {
		err = 0;
		goto page_hit;
	}

	// 预读128个page，其中parent是indirect node block，从其start + 1
	// 开始最多预读128个page，当然，如果超过parent的范围（下表1018），则只预读
	// 到parent的最后一个page。
	if (parent)
		f2fs_ra_node_pages(parent, start + 1, MAX_RA_NODE);

	lock_page(page);

	if (unlikely(page->mapping != NODE_MAPPING(sbi))) {
		f2fs_put_page(page, 1);
		goto repeat;
	}

	if (unlikely(!PageUptodate(page))) {
		err = -EIO;
		goto out_err;
	}

	if (!f2fs_inode_chksum_verify(sbi, page)) {
		err = -EFSBADCRC;
		goto out_err;
	}
page_hit:
	// TODO：会存在这样的场景吗？？？文件系统一致性出错了？
	if (likely(nid == nid_of_node(page)))
		return page;

	f2fs_warn(sbi, "inconsistent node block, nid:%lu, node_footer[nid:%u,ino:%u,ofs:%u,cpver:%llu,blkaddr:%u]",
			  nid, nid_of_node(page), ino_of_node(page),
			  ofs_of_node(page), cpver_of_node(page),
			  next_blkaddr_of_node(page));
	set_sbi_flag(sbi, SBI_NEED_FSCK);
	err = -EINVAL;
out_err:
	ClearPageUptodate(page);
out_put_err:
	/* ENOENT comes from read_node_page which is not an error. */
	// TODO：
	if (err != -ENOENT)
		f2fs_handle_page_eio(sbi, page->index, NODE);
	f2fs_put_page(page, 1);
	return ERR_PTR(err);
}

// 读取nid对应的page
struct page *f2fs_get_node_page(struct f2fs_sb_info *sbi, pgoff_t nid)
{
	return __get_node_page(sbi, nid, NULL, 0);
}

// 支持预读，从indirect node中的start + 1开始预读128个page
struct page *f2fs_get_node_page_ra(struct page *parent, int start)
{
	struct f2fs_sb_info *sbi = F2FS_P_SB(parent);
	nid_t nid = get_nid(parent, start, false);

	return __get_node_page(sbi, nid, parent, start);
}

// 将node page的inline data数据下刷
// 注意：调用该接口时，page不能持锁
static void flush_inline_data(struct f2fs_sb_info *sbi, nid_t ino)
{
	struct inode *inode;
	struct page *page;
	int ret;

	/* should flush inline_data before evict_inode */
	inode = ilookup(sbi->sb, ino);
	if (!inode)
		return;

	// 获取inline data对应的page cache（默认的index是0？可能是应为如果有inline data数据，
	// 必然是开头的4KB内，所以用0号的index）
	page = f2fs_pagecache_get_page(inode->i_mapping, 0,
					FGP_LOCK|FGP_NOWAIT, 0);
	if (!page)
		goto iput_out;

	// 如果inline data的数据不可用，那也无需下刷
	if (!PageUptodate(page))
		goto page_out;

	// 如果inline data的数据没有被写过，同样无需下刷
	if (!PageDirty(page))
		goto page_out;

	// 清除inline data页的dirty属性
	if (!clear_page_dirty_for_io(page))
		goto page_out;

	// 将inline数据下刷，并调整对应的统计数据
	ret = f2fs_write_inline_data(inode, page);
	inode_dec_dirty_pages(inode);
	f2fs_remove_dirty_inode(inode);
	if (ret)
		// 如果下刷失败，则需要回退修改
		set_page_dirty(page);
page_out:
	f2fs_put_page(page, 1);
iput_out:
	iput(inode);
}

// TODO：与原子操作有关
static struct page *last_fsync_dnode(struct f2fs_sb_info *sbi, nid_t ino)
{
	pgoff_t index;
	struct folio_batch fbatch;
	struct page *last_page = NULL;
	int nr_folios;

	folio_batch_init(&fbatch);
	index = 0;

	while ((nr_folios = filemap_get_folios_tag(NODE_MAPPING(sbi), &index,
					(pgoff_t)-1, PAGECACHE_TAG_DIRTY,
					&fbatch))) {
		int i;

		for (i = 0; i < nr_folios; i++) {
			struct page *page = &fbatch.folios[i]->page;

			if (unlikely(f2fs_cp_error(sbi))) {
				f2fs_put_page(last_page, 0);
				folio_batch_release(&fbatch);
				return ERR_PTR(-EIO);
			}

			if (!IS_DNODE(page) || !is_cold_node(page))
				continue;
			if (ino_of_node(page) != ino)
				continue;

			lock_page(page);

			if (unlikely(page->mapping != NODE_MAPPING(sbi))) {
continue_unlock:
				unlock_page(page);
				continue;
			}
			if (ino_of_node(page) != ino)
				goto continue_unlock;

			if (!PageDirty(page)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if (last_page)
				f2fs_put_page(last_page, 0);

			get_page(page);
			last_page = page;
			unlock_page(page);
		}
		folio_batch_release(&fbatch);
		cond_resched();
	}
	return last_page;
}

// 注意：使用本需要先对page持锁，同时page是非dirty状态，bdi任务不会重新下刷该page
static int __write_node_page(struct page *page, bool atomic, bool *submitted,
				struct writeback_control *wbc, bool do_balance,
				enum iostat_type io_type, unsigned int *seq_id)
{
	struct f2fs_sb_info *sbi = F2FS_P_SB(page);
	nid_t nid;
	struct node_info ni;
	// 初始化fio，与block层的bio对应
	struct f2fs_io_info fio = {
		.sbi = sbi,
		// 一个node所属的inode记录在footer.ino中
		.ino = ino_of_node(page),
		.type = NODE,
		// REQ_OP_WRITE表示写设备的扇区
		.op = REQ_OP_WRITE,
		.op_flags = wbc_to_write_flags(wbc),
		.page = page,
		.encrypted_page = NULL,
		.submitted = 0,
		.io_type = io_type,
		.io_wbc = wbc,
	};
	unsigned int seq;

	trace_f2fs_writepage(page, NODE);

	// 当前存在错误，无法写CP，那自然也无法写node，直接返回
	if (unlikely(f2fs_cp_error(sbi))) {
		ClearPageUptodate(page);
		dec_page_count(sbi, F2FS_DIRTY_NODES);
		unlock_page(page);
		return 0;
	}

	// 当前文件系统正在恢复流程，也不允许写node page。
	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto redirty_out;

	// TODO：
	if (!is_sbi_flag_set(sbi, SBI_CP_DISABLED) &&
			wbc->sync_mode == WB_SYNC_NONE &&
			IS_DNODE(page) && is_cold_node(page))
		goto redirty_out;

	/* get old block addr of this node page */
	// 获取page对应的node id，记录在footer.nid中
	nid = nid_of_node(page);
	f2fs_bug_on(sbi, page->index != nid);

	// 获取nid对应的管理信息node_info
	if (f2fs_get_node_info(sbi, nid, &ni, !do_balance))
		goto redirty_out;

	// TODO：
	if (wbc->for_reclaim) {
		if (!f2fs_down_read_trylock(&sbi->node_write))
			goto redirty_out;
	} else {
		f2fs_down_read(&sbi->node_write);
	}

	/* This page is already truncated */
	// 如果在下刷过程中，page已经被回收（删除）
	if (unlikely(ni.blk_addr == NULL_ADDR)) {
		// 清空uptodata标记，表示缓存中的page无效了，需要从存储
		// 介质读取
		ClearPageUptodate(page);
		dec_page_count(sbi, F2FS_DIRTY_NODES);
		f2fs_up_read(&sbi->node_write);
		unlock_page(page);
		return 0;
	}

	// 如果page对应的node block地址是无效的（segment中没有记录该block可用等），
	// 则走失败流程
	if (__is_valid_data_blkaddr(ni.blk_addr) &&
		!f2fs_is_valid_blkaddr(sbi, ni.blk_addr,
					DATA_GENERIC_ENHANCE)) {
		f2fs_up_read(&sbi->node_write);
		goto redirty_out;
	}

	// 如果则是一个原子文件，并且mount的时候没有设置NOBARRIER标记（表示物理层无法保证cache在掉电时
	// 自动刷入到设备），而且不是blkzoned（TODO：），则本次需要对设备进行flush操作，确保本次写入设备
	// cache的数据，能到达存储介质（因为本次是原子文件的操作）。
	if (atomic && !test_opt(sbi, NOBARRIER) && !f2fs_sb_has_blkzoned(sbi))
		fio.op_flags |= REQ_PREFLUSH | REQ_FUA;

	/* should add to global list before clearing PAGECACHE status */
	// 如果本次是下刷普通文件的direct node page，则放入到一个全局链表中，在fsync场景会一直等到
	// bio结束后，再从全局链表中将page摘掉，确保本次io已经完成。
	if (f2fs_in_warm_node_list(sbi, page)) {
		seq = f2fs_add_fsync_node_entry(sbi, page);
		if (seq_id)
			*seq_id = seq;
	}

	// 设置page的writeback属性，在bio结束时（end_io流程）会清除该属性
	set_page_writeback(page);

	// 设置old_blkaddr，在io之前，会根据node分配策略，分配new_blkaddr，
	// 表示nid下刷后对应的blkaddr
	fio.old_blkaddr = ni.blk_addr;
	// 向bio层提交写操作
	f2fs_do_write_node_page(nid, &fio);
	// 更新nid对应的blkaddr
	set_node_addr(sbi, &ni, fio.new_blkaddr, is_fsync_dnode(page));
	// 更新dirty node的统计数据
	dec_page_count(sbi, F2FS_DIRTY_NODES);
	f2fs_up_read(&sbi->node_write);

	// TODO：
	if (wbc->for_reclaim) {
		f2fs_submit_merged_write_cond(sbi, NULL, page, 0, NODE);
		submitted = NULL;
	}

	// 解锁page，其他任务可以对page重新dirty和下刷
	unlock_page(page);

	// TODO：
	if (unlikely(f2fs_cp_error(sbi))) {
		f2fs_submit_merged_write(sbi, NODE);
		submitted = NULL;
	}

	// TODO：记录本次是否向bio层提交过写操作，可能本次的写操作被合并了？？？
	if (submitted)
		*submitted = fio.submitted;

	// TODO：
	if (do_balance)
		f2fs_balance_fs(sbi, false);
	return 0;

redirty_out:
	// 如果本次下刷page失败，则重新置为dirty，放入到dirty链表，等待再次被下刷。
	redirty_page_for_writepage(wbc, page);
	return AOP_WRITEPAGE_ACTIVATE;
}

int f2fs_move_node_page(struct page *node_page, int gc_type)
{
	int err = 0;

	if (gc_type == FG_GC) {
		struct writeback_control wbc = {
			.sync_mode = WB_SYNC_ALL,
			.nr_to_write = 1,
			.for_reclaim = 0,
		};

		f2fs_wait_on_page_writeback(node_page, NODE, true, true);

		set_page_dirty(node_page);

		if (!clear_page_dirty_for_io(node_page)) {
			err = -EAGAIN;
			goto out_page;
		}

		if (__write_node_page(node_page, false, NULL,
					&wbc, false, FS_GC_NODE_IO, NULL)) {
			err = -EAGAIN;
			unlock_page(node_page);
		}
		goto release_page;
	} else {
		/* set page dirty and write it */
		if (!PageWriteback(node_page))
			set_page_dirty(node_page);
	}
out_page:
	unlock_page(node_page);
release_page:
	f2fs_put_page(node_page, 0);
	return err;
}

// 将单个page下刷
static int f2fs_write_node_page(struct page *page,
				struct writeback_control *wbc)
{
	// page：待下刷的page
	// atomic：false，该page不是原子文件
	// TODO：submitted？
	// wbc：回写控制结构体，作为bio的配置
	// do_balance：？
	// io_type：FS_NODE_IO，本次IO类型是NODE page的io
	// seq_id：NULL，本次下刷的序列号，只有fsync场景才关注该参数
	return __write_node_page(page, false, NULL, wbc, false,
						FS_NODE_IO, NULL);
}

// 在fsync或者fsyncdata流程中调用
// 注意：该函数没有同步的语义，需要上层保证同步
int f2fs_fsync_node_pages(struct f2fs_sb_info *sbi, struct inode *inode,
			struct writeback_control *wbc, bool atomic,
			unsigned int *seq_id)
{
	pgoff_t index;
	struct folio_batch fbatch;
	int ret = 0;
	struct page *last_page = NULL;
	bool marked = false;
	nid_t ino = inode->i_ino;
	int nr_folios;
	int nwritten = 0;

	// TODO：原子操作相关
	if (atomic) {
		last_page = last_fsync_dnode(sbi, ino);
		if (IS_ERR_OR_NULL(last_page))
			return PTR_ERR_OR_ZERO(last_page);
	}
retry:
	// TODO：
	folio_batch_init(&fbatch);
	index = 0;

	// 获取所有被标记为dirty的页，准备将其下刷
	while ((nr_folios = filemap_get_folios_tag(NODE_MAPPING(sbi), &index,
					(pgoff_t)-1, PAGECACHE_TAG_DIRTY,
					&fbatch))) {
		int i;

		// 遍历所有获取到的脏页
		for (i = 0; i < nr_folios; i++) {
			struct page *page = &fbatch.folios[i]->page;
			bool submitted = false;

			if (unlikely(f2fs_cp_error(sbi))) {
				f2fs_put_page(last_page, 0);
				folio_batch_release(&fbatch);
				ret = -EIO;
				goto out;
			}

			// TODO：fsync流程只针对direct node？其他的node page
			// 无需在fsync流程处理，配合前滚恢复可以最终恢复成功（indirect
			// node的数据可以通过direct node反推出来，所以只需确保inode + 
			// direct node数据已经下刷完毕，就有办法恢复）
			if (!IS_DNODE(page) || !is_cold_node(page))
				continue;
			// 如果当前的脏页不属于代下刷的文件，则跳过（可见所有的脏页放在全局表中）
			if (ino_of_node(page) != ino)
				continue;

			// 对page上锁，确保其他任务不会修改page的管理属性（但page对应的物理页还是可以
			// 被修改？也即在fsync没有真正完成前，page cache的数据可能还一直被修改）。
			// 此处上锁也可以确保该page不会被bdi任务下刷（同时也确保bdi任务对该page
			// 提交完bio之后，才可以继续往下提交bio？）
			lock_page(page);

			// 如果该page不是node类型，则跳过（其实上面获取dirty page的时候就已经根据
			// NODE_MAPPING的条件获取的，只是有可能上面获取脏页的时候，这个page是node类型
			// 但是后面被重新用于其他类型了，所以这里要判断一下）
			if (unlikely(page->mapping != NODE_MAPPING(sbi))) {
continue_unlock:
				unlock_page(page);
				continue;
			}

			// 该判断上面已经判断过一次了，这里需要再判断一次是因为上面的判断是在加锁之前，
			// 有可能在判断结束后，被修改了，所以这里需要重新判断以下，往下就不会被修改了
			if (ino_of_node(page) != ino)
				goto continue_unlock;

			// 如果该page不是脏页，同时该page不是原子操作的最后一个page，则跳过。
			// 同上，上面的循环获取到的脏页，可能正在被回写，此时已经回写完成了，所以
			// 现在不是dirty了，这时候无需重新下刷page。
			if (!PageDirty(page) && page != last_page) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			// 同上，该page可能在正被回写（上面提到正在被回写的page，还是可以被修改），
			// 需要等到page完成上一次的回写，才会将新写入page cache的内容下刷。
			f2fs_wait_on_page_writeback(page, NODE, true, true);

			// TODO：设置fsync标记（用于前滚恢复？）
			set_fsync_mark(page, 0);
			set_dentry_mark(page, 0);

			if (!atomic || page == last_page) {
				set_fsync_mark(page, 1);
				percpu_counter_inc(&sbi->rf_node_block_count);
				if (IS_INODE(page)) {
					if (is_inode_flag_set(inode,
								FI_DIRTY_INODE))
						f2fs_update_inode(inode, page);
					set_dentry_mark(page,
						f2fs_need_dentry_mark(sbi, ino));
				}
				/* may be written by other thread */
				// TODO：针对atomic的文件，尽管该page不是dirty，仍然需要下刷。
				// 这里为了兼容下面的clear dirty流程，需要重新置为dirty
				if (!PageDirty(page))
					set_page_dirty(page);
			}

			// 清除page的dirty属性，避免bdi任务再次提交？
			if (!clear_page_dirty_for_io(page))
				goto continue_unlock;

			// 将写page操作提交给bio
			ret = __write_node_page(page, atomic &&
						page == last_page,
						&submitted, wbc, true,
						FS_NODE_IO, seq_id);
			if (ret) {
				unlock_page(page);
				f2fs_put_page(last_page, 0);
				break;
			} else if (submitted) {
				// 如果本次的确提交了bio，则刷新统计数目
				nwritten++;
			}

			// TODO：针对atomic文件？？？
			if (page == last_page) {
				f2fs_put_page(page, 0);
				marked = true;
				break;
			}
		}
		folio_batch_release(&fbatch);
		cond_resched();

		if (ret || marked)
			break;
	}

	// TODO：原子文件提交失败？需要一直提交，确保原子语义？
	if (!ret && atomic && !marked) {
		f2fs_debug(sbi, "Retry to write fsync mark: ino=%u, idx=%lx",
			   ino, last_page->index);
		lock_page(last_page);
		f2fs_wait_on_page_writeback(last_page, NODE, true, true);
		set_page_dirty(last_page);
		unlock_page(last_page);
		goto retry;
	}
out:
	// 将sbi中缓存的bio提交给bio层
	if (nwritten)
		f2fs_submit_merged_write_cond(sbi, NULL, NULL, ino, NODE);
	return ret ? -EIO : 0;
}

// 查找存放到inode_hashtable的脏inode
static int f2fs_match_ino(struct inode *inode, unsigned long ino, void *data)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	bool clean;

	if (inode->i_ino != ino)
		return 0;

	// 只有脏的inode才会放到inode_hashtable中？？？
	if (!is_inode_flag_set(inode, FI_DIRTY_INODE))
		return 0;

	spin_lock(&sbi->inode_lock[DIRTY_META]);
	// 通过gdirty_list节点放入到inode_hashtable中
	clean = list_empty(&F2FS_I(inode)->gdirty_list);
	spin_unlock(&sbi->inode_lock[DIRTY_META]);

	// 如果没有放入到全局链表中，则无需处理
	if (clean)
		return 0;

	// 增加inode的引用计数？
	inode = igrab(inode);
	if (!inode)
		return 0;
	return 1;
}

// 将脏的inode页下刷（此处处理的应该是VFS层的inode）
static bool flush_dirty_inode(struct page *page)
{
	struct f2fs_sb_info *sbi = F2FS_P_SB(page);
	struct inode *inode;
	nid_t ino = ino_of_node(page);

	// 在系统全局inode_hashtable链表中找到page对应的inode
	inode = find_inode_nowait(sbi->sb, ino, f2fs_match_ino, NULL);
	if (!inode)
		return false;

	// 找到脏inode页，将inode脏数据更新到f2fs的inode管理结构体，并将page下刷
	f2fs_update_inode(inode, page);
	unlock_page(page);

	iput(inode);
	return true;
}

// 将inline中的数据下刷
void f2fs_flush_inline_data(struct f2fs_sb_info *sbi)
{
	pgoff_t index = 0;
	struct folio_batch fbatch;
	int nr_folios;

	folio_batch_init(&fbatch);

	// 获取所有脏的node页
	while ((nr_folios = filemap_get_folios_tag(NODE_MAPPING(sbi), &index,
					(pgoff_t)-1, PAGECACHE_TAG_DIRTY,
					&fbatch))) {
		int i;

		for (i = 0; i < nr_folios; i++) {
			struct page *page = &fbatch.folios[i]->page;

			// 只处理脏的direct node页
			if (!IS_DNODE(page))
				continue;

			lock_page(page);

			// 如果page不再是node类型的页，则跳过
			if (unlikely(page->mapping != NODE_MAPPING(sbi))) {
continue_unlock:
				unlock_page(page);
				continue;
			}

			// 如果page已经不是脏页，同样无需处理
			if (!PageDirty(page)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			/* flush inline_data, if it's async context. */
			// 只处理有inline_data的页（TODO：只有inode才有inline data？？？）
			if (page_private_inline(page)) {
				// 清除page的private_inline属性，避免一个page被反复下刷
				clear_page_private_inline(page);
				unlock_page(page);
				// 下刷inline data数据
				flush_inline_data(sbi, ino_of_node(page));
				continue;
			}
			unlock_page(page);
		}
		folio_batch_release(&fbatch);
		cond_resched();
	}
}

// 将连续的脏node page回写
int f2fs_sync_node_pages(struct f2fs_sb_info *sbi,
				struct writeback_control *wbc,
				bool do_balance, enum iostat_type io_type)
{
	pgoff_t index;
	struct folio_batch fbatch;
	int step = 0;
	int nwritten = 0;
	int ret = 0;
	int nr_folios, done = 0;

	folio_batch_init(&fbatch);

next_step:
	index = 0;

	// 获取脏node page页
	while (!done && (nr_folios = filemap_get_folios_tag(NODE_MAPPING(sbi),
				&index, (pgoff_t)-1, PAGECACHE_TAG_DIRTY,
				&fbatch))) {
		int i;

		for (i = 0; i < nr_folios; i++) {
			struct page *page = &fbatch.folios[i]->page;
			bool submitted = false;

			/* give a priority to WB_SYNC threads */
			// 如果已经回写完成，则结束本次回写流程
			if (atomic_read(&sbi->wb_sync_req[NODE]) &&
					wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}

			/*
			 * flushing sequence with step:
			 * 0. indirect nodes
			 * 1. dentry dnodes
			 * 2. file dnodes
			 */
			// 按步骤进行node page下刷
			// 第0步处理indirect nodes
			if (step == 0 && IS_DNODE(page))
				continue;
			// 第1步处理dentry dnodes（direct node + hot_node）
			if (step == 1 && (!IS_DNODE(page) ||
						is_cold_node(page)))
				continue;
			// 第2步处理file dnodes（direct node + cold node）
			if (step == 2 && (!IS_DNODE(page) ||
						!is_cold_node(page)))
				continue;
lock_node:
			if (wbc->sync_mode == WB_SYNC_ALL)
				lock_page(page);
			else if (!trylock_page(page))
				continue;

			// 确保page是node类型
			if (unlikely(page->mapping != NODE_MAPPING(sbi))) {
continue_unlock:
				unlock_page(page);
				continue;
			}

			// 如果page非脏，则跳过
			if (!PageDirty(page)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			/* flush inline_data/inode, if it's async context. */
			// 如果是异步场景，还需要下刷inline数据和inode（TODO：为什么通过do_balance判断？）
			if (!do_balance)
				goto write_node;

			/* flush inline_data */
			// 如果node有inline data，则将inline数据下刷
			if (page_private_inline(page)) {
				clear_page_private_inline(page);
				unlock_page(page);
				flush_inline_data(sbi, ino_of_node(page));
				goto lock_node;
			}

			/* flush dirty inode */
			// 如果是inode，还需要将脏的inode信息下刷
			if (IS_INODE(page) && flush_dirty_inode(page))
				goto lock_node;
write_node:
			// 等待page回写完成
			f2fs_wait_on_page_writeback(page, NODE, true, true);

			// 清除page的dirty属性，避免bdi重复提交
			if (!clear_page_dirty_for_io(page))
				goto continue_unlock;

			set_fsync_mark(page, 0);
			set_dentry_mark(page, 0);

			ret = __write_node_page(page, false, &submitted,
						wbc, do_balance, io_type, NULL);
			if (ret)
				unlock_page(page);
			else if (submitted)
				nwritten++;

			if (--wbc->nr_to_write == 0)
				break;
		}
		folio_batch_release(&fbatch);
		cond_resched();

		if (wbc->nr_to_write == 0) {
			step = 2;
			break;
		}
	}

	if (step < 2) {
		// TODO：如果不是SBI_CP_DISABLED标记，并且非WB_SYNC_NONE同步模式，
		// 而且是dentry dnode回写结束后，则跳过？？？
		if (!is_sbi_flag_set(sbi, SBI_CP_DISABLED) &&
				wbc->sync_mode == WB_SYNC_NONE && step == 1)
			goto out;
		step++;
		goto next_step;
	}
out:
	// 将sbi中的缓存bio提交给block层
	if (nwritten)
		f2fs_submit_merged_write(sbi, NODE);

	if (unlikely(f2fs_cp_error(sbi)))
		return -EIO;
	return ret;
}

// 等待node page回写完成，在end_io中会将放入到fsync_node_list链表的数据摘除
int f2fs_wait_on_node_pages_writeback(struct f2fs_sb_info *sbi,
						unsigned int seq_id)
{
	struct fsync_node_entry *fn;
	struct page *page;
	struct list_head *head = &sbi->fsync_node_list;
	unsigned long flags;
	unsigned int cur_seq_id = 0;
	int ret2, ret = 0;

	while (seq_id && cur_seq_id < seq_id) {
		spin_lock_irqsave(&sbi->fsync_node_lock, flags);
		if (list_empty(head)) {
			spin_unlock_irqrestore(&sbi->fsync_node_lock, flags);
			break;
		}
		fn = list_first_entry(head, struct fsync_node_entry, list);
		if (fn->seq_id > seq_id) {
			spin_unlock_irqrestore(&sbi->fsync_node_lock, flags);
			break;
		}
		// 每一次执行fsync或者fsyncdata操作，都会将seq_id增加1,用来记录本次fsync操作。
		// 通过seq_id，每个任务能知道自己提交的page有没被回写完成
		cur_seq_id = fn->seq_id;
		page = fn->page;
		get_page(page);
		spin_unlock_irqrestore(&sbi->fsync_node_lock, flags);

		f2fs_wait_on_page_writeback(page, NODE, true, false);

		put_page(page);

		if (ret)
			break;
	}

	ret2 = filemap_check_errors(NODE_MAPPING(sbi));
	if (!ret)
		ret = ret2;

	return ret;
}

// 将连续多个page下刷，范围是wbc中的range_start ~ range_end
static int f2fs_write_node_pages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct f2fs_sb_info *sbi = F2FS_M_SB(mapping);
	struct blk_plug plug;
	long diff;

	// 如果文件系统正在恢复流程，则不进行回写操作
	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto skip_write;

	/* balancing f2fs's metadata in background */
	// TODO：
	f2fs_balance_fs_bg(sbi, true);

	/* collect a number of dirty node pages and write together */
	// 如果当前不是WB_SYNC_ALL回写模式，并且dirty nodes的数目少于阈值，
	// 则本次暂不回写，等待有足够多的脏页才回写
	if (wbc->sync_mode != WB_SYNC_ALL &&
			get_pages(sbi, F2FS_DIRTY_NODES) <
					nr_pages_to_skip(sbi, NODE))
		goto skip_write;

	// 如果本次是WB_SYNC_ALL的回写模式，则增加相应统计数
	if (wbc->sync_mode == WB_SYNC_ALL)
		atomic_inc(&sbi->wb_sync_req[NODE]);
	else if (atomic_read(&sbi->wb_sync_req[NODE])) {
		/* to avoid potential deadlock */
		// 或者本次不是WB_SYNC_ALL模式，并且已经超过dirty nodes的阈值，
		// 但wb_sync_req的请求次数是0（TODO：表示plug的场景？？？）
		if (current->plug)
			blk_finish_plug(current->plug);
		goto skip_write;
	}

	trace_f2fs_writepages(mapping->host, wbc, NODE);

	diff = nr_pages_to_write(sbi, NODE, wbc);
	// 通过plug机制将node page回写
	blk_start_plug(&plug);
	f2fs_sync_node_pages(sbi, wbc, true, FS_NODE_IO);
	blk_finish_plug(&plug);
	wbc->nr_to_write = max((long)0, wbc->nr_to_write - diff);

	if (wbc->sync_mode == WB_SYNC_ALL)
		atomic_dec(&sbi->wb_sync_req[NODE]);
	return 0;

skip_write:
	wbc->pages_skipped += get_pages(sbi, F2FS_DIRTY_NODES);
	trace_f2fs_writepages(mapping->host, wbc, NODE);
	return 0;
}

static bool f2fs_dirty_node_folio(struct address_space *mapping,
		struct folio *folio)
{
	trace_f2fs_set_page_dirty(&folio->page, NODE);

	// 如果page没有标记uptodata属性，则标记uptodata属性
	// 该属性表示page cache中的page直接读写，无需从存储
	// 介质读取。
	if (!folio_test_uptodate(folio))
		folio_mark_uptodate(folio);
#ifdef CONFIG_F2FS_CHECK_FS
	if (IS_INODE(&folio->page))
		f2fs_inode_chksum_set(F2FS_M_SB(mapping), &folio->page);
#endif
	// 将page置dirty，如果成功则增加计数，并设置page的私有属性（PAGE_PRIVATE_REF_RESOURCE）
	if (filemap_dirty_folio(mapping, folio)) {
		inc_page_count(F2FS_M_SB(mapping), F2FS_DIRTY_NODES);
		set_page_private_reference(&folio->page);
		return true;
	}
	return false;
}

/*
 * Structure of the f2fs node operations
 */
const struct address_space_operations f2fs_node_aops = {
	.writepage	= f2fs_write_node_page,
	.writepages	= f2fs_write_node_pages,
	.dirty_folio	= f2fs_dirty_node_folio,
	.invalidate_folio = f2fs_invalidate_folio,
	.release_folio	= f2fs_release_folio,
	.migrate_folio	= filemap_migrate_folio,
};

// 在free_nid_root中查找特定nid
static struct free_nid *__lookup_free_nid_list(struct f2fs_nm_info *nm_i,
						nid_t n)
{
	return radix_tree_lookup(&nm_i->free_nid_root, n);
}

// 插入一个free_nid到free_nid_root和free_nid_list
static int __insert_free_nid(struct f2fs_sb_info *sbi,
				struct free_nid *i)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	int err = radix_tree_insert(&nm_i->free_nid_root, i->nid, i);

	if (err)
		return err;

	nm_i->nid_cnt[FREE_NID]++;
	list_add_tail(&i->list, &nm_i->free_nid_list);
	return 0;
}

// 从free_nid_list和free_nid_root中移除一个node。
static void __remove_free_nid(struct f2fs_sb_info *sbi,
			struct free_nid *i, enum nid_state state)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);

	f2fs_bug_on(sbi, state != i->state);
	nm_i->nid_cnt[state]--;
	if (state == FREE_NID)
		list_del(&i->list);
	radix_tree_delete(&nm_i->free_nid_root, i->nid);
}

// 将free nid从free_nid_list摘除或者添加
static void __move_free_nid(struct f2fs_sb_info *sbi, struct free_nid *i,
			enum nid_state org_state, enum nid_state dst_state)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);

	f2fs_bug_on(sbi, org_state != i->state);
	i->state = dst_state;
	nm_i->nid_cnt[org_state]--;
	nm_i->nid_cnt[dst_state]++;

	switch (dst_state) {
	case PREALLOC_NID:
		list_del(&i->list);
		break;
	case FREE_NID:
		list_add_tail(&i->list, &nm_i->free_nid_list);
		break;
	default:
		BUG_ON(1);
	}
}

// TODO：遍历nat_block_bitmap，如果有一个block不可用。
bool f2fs_nat_bitmap_enabled(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned int i;
	bool ret = true;

	f2fs_down_read(&nm_i->nat_tree_lock);
	for (i = 0; i < nm_i->nat_blocks; i++) {
		if (!test_bit_le(i, nm_i->nat_block_bitmap)) {
			ret = false;
			break;
		}
	}
	f2fs_up_read(&nm_i->nat_tree_lock);

	return ret;
}

// 更新free_nid_bitmap，在申请或者释放free_nid时会调用
static void update_free_nid_bitmap(struct f2fs_sb_info *sbi, nid_t nid,
							bool set, bool build)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned int nat_ofs = NAT_BLOCK_OFFSET(nid);
	unsigned int nid_ofs = nid - START_NID(nid);

	if (!test_bit_le(nat_ofs, nm_i->nat_block_bitmap))
		return;

	if (set) {
		if (test_bit_le(nid_ofs, nm_i->free_nid_bitmap[nat_ofs]))
			return;
		__set_bit_le(nid_ofs, nm_i->free_nid_bitmap[nat_ofs]);
		nm_i->free_nid_count[nat_ofs]++;
	} else {
		if (!test_bit_le(nid_ofs, nm_i->free_nid_bitmap[nat_ofs]))
			return;
		__clear_bit_le(nid_ofs, nm_i->free_nid_bitmap[nat_ofs]);
		if (!build)
			nm_i->free_nid_count[nat_ofs]--;
	}
}

/* return if the nid is recognized as free */
// 新增一个free nid到free_nid_root和free_nid_list。
static bool add_free_nid(struct f2fs_sb_info *sbi,
				nid_t nid, bool build, bool update)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *i, *e;
	struct nat_entry *ne;
	int err = -EINVAL;
	bool ret = false;

	/* 0 nid should not be used */
	if (unlikely(nid == 0))
		return false;

	if (unlikely(f2fs_check_nid_range(sbi, nid)))
		return false;

	i = f2fs_kmem_cache_alloc(free_nid_slab, GFP_NOFS, true, NULL);
	i->nid = nid;
	i->state = FREE_NID;

	radix_tree_preload(GFP_NOFS | __GFP_NOFAIL);

	spin_lock(&nm_i->nid_list_lock);

	if (build) {
		/*
		 *   Thread A             Thread B
		 *  - f2fs_create
		 *   - f2fs_new_inode
		 *    - f2fs_alloc_nid
		 *     - __insert_nid_to_list(PREALLOC_NID)
		 *                     - f2fs_balance_fs_bg
		 *                      - f2fs_build_free_nids
		 *                       - __f2fs_build_free_nids
		 *                        - scan_nat_page
		 *                         - add_free_nid
		 *                          - __lookup_nat_cache
		 *  - f2fs_add_link
		 *   - f2fs_init_inode_metadata
		 *    - f2fs_new_inode_page
		 *     - f2fs_new_node_page
		 *      - set_node_addr
		 *  - f2fs_alloc_nid_done
		 *   - __remove_nid_from_list(PREALLOC_NID)
		 *                         - __insert_nid_to_list(FREE_NID)
		 */
		ne = __lookup_nat_cache(nm_i, nid);
		if (ne && (!get_nat_flag(ne, IS_CHECKPOINTED) ||
				nat_get_blkaddr(ne) != NULL_ADDR))
			goto err_out;

		e = __lookup_free_nid_list(nm_i, nid);
		if (e) {
			if (e->state == FREE_NID)
				ret = true;
			goto err_out;
		}
	}
	ret = true;
	err = __insert_free_nid(sbi, i);
err_out:
	if (update) {
		update_free_nid_bitmap(sbi, nid, ret, build);
		if (!build)
			nm_i->available_nids++;
	}
	spin_unlock(&nm_i->nid_list_lock);
	radix_tree_preload_end();

	if (err)
		kmem_cache_free(free_nid_slab, i);
	return ret;
}

// 从free_nid_root和free_nid_list中移除一个free nid。
static void remove_free_nid(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *i;
	bool need_free = false;

	spin_lock(&nm_i->nid_list_lock);
	i = __lookup_free_nid_list(nm_i, nid);
	if (i && i->state == FREE_NID) {
		__remove_free_nid(sbi, i, FREE_NID);
		need_free = true;
	}
	spin_unlock(&nm_i->nid_list_lock);

	if (need_free)
		kmem_cache_free(free_nid_slab, i);
}

// 扫描一个nat block，获取可用的free nid
static int scan_nat_page(struct f2fs_sb_info *sbi,
			struct page *nat_page, nid_t start_nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct f2fs_nat_block *nat_blk = page_address(nat_page);
	block_t blk_addr;
	unsigned int nat_ofs = NAT_BLOCK_OFFSET(start_nid);
	int i;

	// 设置该nat block可用（也即可以通过nat_block_bitmap管理）
	__set_bit_le(nat_ofs, nm_i->nat_block_bitmap);

	i = start_nid % NAT_ENTRY_PER_BLOCK;

	for (; i < NAT_ENTRY_PER_BLOCK; i++, start_nid++) {
		if (unlikely(start_nid >= nm_i->max_nid))
			break;

		blk_addr = le32_to_cpu(nat_blk->entries[i].block_addr);

		// TODO：新的nat block不应该存在NEW_ADDR类型的node block？
		if (blk_addr == NEW_ADDR)
			return -EINVAL;

		// 如果该node block未被使用，则放到free_nid_list中
		// 如果该node block已经被使用，则将free_nid_bitmap对应标记位置上。
		if (blk_addr == NULL_ADDR) {
			add_free_nid(sbi, start_nid, true, true);
		} else {
			spin_lock(&NM_I(sbi)->nid_list_lock);
			update_free_nid_bitmap(sbi, start_nid, false, true);
			spin_unlock(&NM_I(sbi)->nid_list_lock);
		}
	}

	return 0;
}

// 扫描current segment中的journal，处理空闲或者非空闲的nid
static void scan_curseg_cache(struct f2fs_sb_info *sbi)
{
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	struct f2fs_journal *journal = curseg->journal;
	int i;

	down_read(&curseg->journal_rwsem);
	for (i = 0; i < nats_in_cursum(journal); i++) {
		block_t addr;
		nid_t nid;

		addr = le32_to_cpu(nat_in_journal(journal, i).block_addr);
		nid = le32_to_cpu(nid_in_journal(journal, i));
		if (addr == NULL_ADDR)
			add_free_nid(sbi, nid, true, false);
		else
			remove_free_nid(sbi, nid);
	}
	up_read(&curseg->journal_rwsem);
}

// 扫描现有标记可用的nat block，将空闲的free nid放到链表中，在
// 读取存储介质上的nat block之前调用，为了减少读取nat block的次数
static void scan_free_nid_bits(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned int i, idx;
	nid_t nid;

	f2fs_down_read(&nm_i->nat_tree_lock);

	for (i = 0; i < nm_i->nat_blocks; i++) {
		if (!test_bit_le(i, nm_i->nat_block_bitmap))
			continue;
		if (!nm_i->free_nid_count[i])
			continue;
		for (idx = 0; idx < NAT_ENTRY_PER_BLOCK; idx++) {
			idx = find_next_bit_le(nm_i->free_nid_bitmap[i],
						NAT_ENTRY_PER_BLOCK, idx);
			if (idx >= NAT_ENTRY_PER_BLOCK)
				break;

			nid = i * NAT_ENTRY_PER_BLOCK + idx;
			add_free_nid(sbi, nid, true, false);

			if (nm_i->nid_cnt[FREE_NID] >= MAX_FREE_NIDS)
				goto out;
		}
	}
out:
	scan_curseg_cache(sbi);

	f2fs_up_read(&nm_i->nat_tree_lock);
}

// 扫描nat block，将空闲的free nid放到free_nid_list链表，用于分配。
static int __f2fs_build_free_nids(struct f2fs_sb_info *sbi,
						bool sync, bool mount)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	int i = 0, ret;
	// 下一个将要被扫描的node id
	nid_t nid = nm_i->next_scan_nid;

	// 如果已经超过最大的node id号，则重新从0号开始
	if (unlikely(nid >= nm_i->max_nid))
		nid = 0;

	// 对齐，从一个NAT block的起始node id开始扫描（因为读取是以block为粒度读取的）
	if (unlikely(nid % NAT_ENTRY_PER_BLOCK))
		nid = NAT_BLOCK_OFFSET(nid) * NAT_ENTRY_PER_BLOCK;

	/* Enough entries */
	// 如果free_nid_list中有足够的空闲node，则无需通过扫描NAT区域
	if (nm_i->nid_cnt[FREE_NID] >= NAT_ENTRY_PER_BLOCK)
		return 0;

	// TODO：
	if (!sync && !f2fs_available_free_memory(sbi, FREE_NIDS))
		return 0;

	// 如果不是mount的流程，则通过（现有已经可用的nat block中）free_nid_bitmap
	// 找到一定数量空闲的node，确保free_nid_list中空闲的node数量超过MAX_FREE_NIDS。
	if (!mount) {
		/* try to find free nids in free_nid_bitmap */
		scan_free_nid_bits(sbi);

		if (nm_i->nid_cnt[FREE_NID] >= NAT_ENTRY_PER_BLOCK)
			return 0;
	}

	/* readahead nat pages to be scanned */
	// 从nid开始，读取FREE_NID_PAGES个nat block page到mate对应的mapping。
	f2fs_ra_meta_pages(sbi, NAT_BLOCK_OFFSET(nid), FREE_NID_PAGES,
							META_NAT, true);

	f2fs_down_read(&nm_i->nat_tree_lock);

	while (1) {
		// 如果当前的nat block不可用，则需要从page cache中取数据
		if (!test_bit_le(NAT_BLOCK_OFFSET(nid),
						nm_i->nat_block_bitmap)) {
			struct page *page = get_current_nat_page(sbi, nid);

			if (IS_ERR(page)) {
				ret = PTR_ERR(page);
			} else {
				ret = scan_nat_page(sbi, page, nid);
				f2fs_put_page(page, 1);
			}

			if (ret) {
				f2fs_up_read(&nm_i->nat_tree_lock);
				f2fs_err(sbi, "NAT is corrupt, run fsck to fix it");
				return ret;
			}
		}

		// 扫描均以block为粒度，这里nid指向下一个nat block。
		nid += (NAT_ENTRY_PER_BLOCK - (nid % NAT_ENTRY_PER_BLOCK));
		if (unlikely(nid >= nm_i->max_nid))
			nid = 0;

		// 上面预读的nat block page已经遍历完毕
		if (++i >= FREE_NID_PAGES)
			break;
	}

	/* go to the next free nat pages to find free nids abundantly */
	// 记录下一次需要遍历的nid（对应的是下一个nat block）。
	nm_i->next_scan_nid = nid;

	/* find free nids from current sum_pages */
	// 需要处理在current segment的journal缓存的nat entry。
	scan_curseg_cache(sbi);

	f2fs_up_read(&nm_i->nat_tree_lock);

	// 异步读取下一次需要遍历的nat block
	f2fs_ra_meta_pages(sbi, NAT_BLOCK_OFFSET(nm_i->next_scan_nid),
					nm_i->ra_nid_pages, META_NAT, false);

	return 0;
}

int f2fs_build_free_nids(struct f2fs_sb_info *sbi, bool sync, bool mount)
{
	int ret;

	mutex_lock(&NM_I(sbi)->build_lock);
	ret = __f2fs_build_free_nids(sbi, sync, mount);
	mutex_unlock(&NM_I(sbi)->build_lock);

	return ret;
}

/*
 * If this function returns success, caller can obtain a new nid
 * from second parameter of this function.
 * The returned nid could be used ino as well as nid when inode is created.
 */
// 该接口用于预留一个free_nid，只有当调用f2fs_alloc_nid_done才真正完成分配。
bool f2fs_alloc_nid(struct f2fs_sb_info *sbi, nid_t *nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *i = NULL;
retry:
	if (time_to_inject(sbi, FAULT_ALLOC_NID))
		return false;

	spin_lock(&nm_i->nid_list_lock);

	if (unlikely(nm_i->available_nids == 0)) {
		spin_unlock(&nm_i->nid_list_lock);
		return false;
	}

	/* We should not use stale free nids created by f2fs_build_free_nids */
	// 尝试先从free_nid_list中分配free_nid，如果没有，则考虑遍历NAT区域获取free_nid。
	// 如果当前正在通过f2fs_build_free_nids分配free_nid，则不从free_nid_list中分配。
	// TODO：这里是避免冲突？
	if (nm_i->nid_cnt[FREE_NID] && !on_f2fs_build_free_nids(nm_i)) {
		f2fs_bug_on(sbi, list_empty(&nm_i->free_nid_list));
		i = list_first_entry(&nm_i->free_nid_list,
					struct free_nid, list);
		*nid = i->nid;

		// 将free_nid从free_nid_list链表摘掉。
		__move_free_nid(sbi, i, FREE_NID, PREALLOC_NID);
		nm_i->available_nids--;

		// 标记nid已经被使用
		update_free_nid_bitmap(sbi, *nid, false, false);

		spin_unlock(&nm_i->nid_list_lock);
		return true;
	}
	spin_unlock(&nm_i->nid_list_lock);

	/* Let's scan nat pages and its caches to get free nids */
	// 如果无法通过free_nid_list分配空闲node，则只能通过扫描NAT区域分配。
	if (!f2fs_build_free_nids(sbi, true, false))
		goto retry;
	return false;
}

/*
 * f2fs_alloc_nid() should be called prior to this function.
 */
// f2fs_alloc_nid只是预留nid，需要通过该接口真正分配free nid，
void f2fs_alloc_nid_done(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *i;

	// 将free nid从free_nid_root删除，并调整对应的状态
	spin_lock(&nm_i->nid_list_lock);
	i = __lookup_free_nid_list(nm_i, nid);
	f2fs_bug_on(sbi, !i);
	__remove_free_nid(sbi, i, PREALLOC_NID);
	spin_unlock(&nm_i->nid_list_lock);

	kmem_cache_free(free_nid_slab, i);
}

/*
 * f2fs_alloc_nid() should be called prior to this function.
 */
// 在f2fs_alloc_nid之后，如果出错，则需要通过该接口释放free_nid空间。
void f2fs_alloc_nid_failed(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *i;
	bool need_free = false;

	if (!nid)
		return;

	spin_lock(&nm_i->nid_list_lock);
	// 找到free_nid_root中对应的free nid。
	i = __lookup_free_nid_list(nm_i, nid);
	f2fs_bug_on(sbi, !i);

	// TODO：如果系统空间不足，则回收free nid的空间？
	if (!f2fs_available_free_memory(sbi, FREE_NIDS)) {
		__remove_free_nid(sbi, i, PREALLOC_NID);
		need_free = true;
	} else {
		// 如果系统空间充足，则继续放到free_nid_list中。
		__move_free_nid(sbi, i, PREALLOC_NID, FREE_NID);
	}

	nm_i->available_nids++;

	// 更新bitmap的内容
	update_free_nid_bitmap(sbi, nid, true, false);

	spin_unlock(&nm_i->nid_list_lock);

	if (need_free)
		kmem_cache_free(free_nid_slab, i);
}

// 尝试从free_nid_list中回收nr_shrink个node block？
int f2fs_try_to_free_nids(struct f2fs_sb_info *sbi, int nr_shrink)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	int nr = nr_shrink;

	// 如果free_nid_list中保存的node block没有达到阈值，则无需回收
	if (nm_i->nid_cnt[FREE_NID] <= MAX_FREE_NIDS)
		return 0;

	if (!mutex_trylock(&nm_i->build_lock))
		return 0;

	while (nr_shrink && nm_i->nid_cnt[FREE_NID] > MAX_FREE_NIDS) {
		struct free_nid *i, *next;
		unsigned int batch = SHRINK_NID_BATCH_SIZE;

		spin_lock(&nm_i->nid_list_lock);
		// 从free_nid_list中回收已经释放的node block。
		list_for_each_entry_safe(i, next, &nm_i->free_nid_list, list) {
			if (!nr_shrink || !batch ||
				nm_i->nid_cnt[FREE_NID] <= MAX_FREE_NIDS)
				break;
			__remove_free_nid(sbi, i, FREE_NID);
			kmem_cache_free(free_nid_slab, i);
			nr_shrink--;
			batch--;
		}
		spin_unlock(&nm_i->nid_list_lock);
	}

	mutex_unlock(&nm_i->build_lock);

	return nr - nr_shrink;
}

// 恢复inode中的xattr数据
int f2fs_recover_inline_xattr(struct inode *inode, struct page *page)
{
	void *src_addr, *dst_addr;
	size_t inline_size;
	struct page *ipage;
	struct f2fs_inode *ri;

	// 获取inode对应的page，inline xattr数据存储在该page中。
	ipage = f2fs_get_node_page(F2FS_I_SB(inode), inode->i_ino);
	if (IS_ERR(ipage))
		return PTR_ERR(ipage);

	ri = F2FS_INODE(page);
	// 如果老的inode中存在inline xattr，但是待恢复的inode并没有inline xttr，则设上相关的标记
	// 如果老的inode中不存在inline xattr，但是待恢复的inode有inline xttr，则清除相关的标记
	if (ri->i_inline & F2FS_INLINE_XATTR) {
		if (!f2fs_has_inline_xattr(inode)) {
			set_inode_flag(inode, FI_INLINE_XATTR);
			stat_inc_inline_xattr(inode);
		}
	} else {
		if (f2fs_has_inline_xattr(inode)) {
			stat_dec_inline_xattr(inode);
			clear_inode_flag(inode, FI_INLINE_XATTR);
		}
		goto update_inode;
	}

	// 老的inode中存在inline xattr，则拷贝到待恢复的inode中
	dst_addr = inline_xattr_addr(inode, ipage);
	src_addr = inline_xattr_addr(inode, page);
	inline_size = inline_xattr_size(inode);

	f2fs_wait_on_page_writeback(ipage, NODE, true, true);
	memcpy(dst_addr, src_addr, inline_size);
update_inode:
	f2fs_update_inode(inode, ipage);
	f2fs_put_page(ipage, 1);
	return 0;
}

// 恢复一个文件的xattr block数据
int f2fs_recover_xattr_data(struct inode *inode, struct page *page)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	nid_t prev_xnid = F2FS_I(inode)->i_xattr_nid;
	nid_t new_xnid;
	struct dnode_of_data dn;
	struct node_info ni;
	struct page *xpage;
	int err;

	// 待恢复的xattr block还不存在，则需要先分配一个block。
	if (!prev_xnid)
		goto recover_xnid;

	/* 1: invalidate the previous xattr nid */
	// 如果待恢复的xattr block已经存在，则需要先释放空间，并重新分配一个block。
	err = f2fs_get_node_info(sbi, prev_xnid, &ni, false);
	if (err)
		return err;

	f2fs_invalidate_blocks(sbi, ni.blk_addr);
	dec_valid_node_count(sbi, inode, false);
	// 释放一个node block
	set_node_addr(sbi, &ni, NULL_ADDR, false);

recover_xnid:
	/* 2: update xattr nid in inode */
	// 分配一个node block，用于新的xattr block
	if (!f2fs_alloc_nid(sbi, &new_xnid))
		return -ENOSPC;

	set_new_dnode(&dn, inode, NULL, NULL, new_xnid);
	xpage = f2fs_new_node_page(&dn, XATTR_NODE_OFFSET);
	if (IS_ERR(xpage)) {
		f2fs_alloc_nid_failed(sbi, new_xnid);
		return PTR_ERR(xpage);
	}

	f2fs_alloc_nid_done(sbi, new_xnid);
	f2fs_update_inode_page(inode);

	/* 3: update and set xattr node page dirty */
	// 将数据拷贝到新的block中
	memcpy(F2FS_NODE(xpage), F2FS_NODE(page), VALID_XATTR_BLOCK_SIZE);

	set_page_dirty(xpage);
	f2fs_put_page(xpage, 1);

	return 0;
}

// 修复一个inode
int f2fs_recover_inode_page(struct f2fs_sb_info *sbi, struct page *page)
{
	struct f2fs_inode *src, *dst;
	nid_t ino = ino_of_node(page);
	struct node_info old_ni, new_ni;
	struct page *ipage;
	int err;

	// 从存储介质中获取该inode的blkaddr
	err = f2fs_get_node_info(sbi, ino, &old_ni, false);
	if (err)
		return err;

	// 由于该blkaddr是分配给inode的，所以要求其一定是NULL_ADDR
	if (unlikely(old_ni.blk_addr != NULL_ADDR))
		return -EINVAL;
retry:
	// 获取inode的页
	ipage = f2fs_grab_cache_page(NODE_MAPPING(sbi), ino, false);
	if (!ipage) {
		memalloc_retry_wait(GFP_NOFS);
		goto retry;
	}

	/* Should not use this inode from free nid list */
	// 从free_nid_root链表中删除该inode,因为当前处于不可用状态
	remove_free_nid(sbi, ino);

	// 设置uptodata标记
	if (!PageUptodate(ipage))
		SetPageUptodate(ipage);
	// 填充该inode的page cache信息，由于其就是一个inode,所有nid和ino参数是同一个
	fill_node_footer(ipage, ino, ino, 0, true);
	// 设置inode为cold
	set_cold_node(ipage, false);

	src = F2FS_INODE(page);
	dst = F2FS_INODE(ipage);

	// 拷贝存储介质中的内容到page cache
	memcpy(dst, src, offsetof(struct f2fs_inode, i_ext));
	// TODO：为什么要修改这些信息？？？
	dst->i_size = 0;
	dst->i_blocks = cpu_to_le64(1);
	dst->i_links = cpu_to_le32(1);
	dst->i_xattr_nid = 0;
	dst->i_inline = src->i_inline & (F2FS_INLINE_XATTR | F2FS_EXTRA_ATTR);
	// 重新计算inline信息
	if (dst->i_inline & F2FS_EXTRA_ATTR) {
		dst->i_extra_isize = src->i_extra_isize;

		if (f2fs_sb_has_flexible_inline_xattr(sbi) &&
			F2FS_FITS_IN_INODE(src, le16_to_cpu(src->i_extra_isize),
							i_inline_xattr_size))
			dst->i_inline_xattr_size = src->i_inline_xattr_size;

		if (f2fs_sb_has_project_quota(sbi) &&
			F2FS_FITS_IN_INODE(src, le16_to_cpu(src->i_extra_isize),
								i_projid))
			dst->i_projid = src->i_projid;

		if (f2fs_sb_has_inode_crtime(sbi) &&
			F2FS_FITS_IN_INODE(src, le16_to_cpu(src->i_extra_isize),
							i_crtime_nsec)) {
			dst->i_crtime = src->i_crtime;
			dst->i_crtime_nsec = src->i_crtime_nsec;
		}
	}

	// 设置NAT表项信息
	new_ni = old_ni;
	new_ni.ino = ino;

	if (unlikely(inc_valid_node_count(sbi, NULL, true)))
		WARN_ON(1);
	// TODO:为什么不能直接用old.blkaddr？因为修改了该inode的内容？需要重新
	// 分配一个node block？
	set_node_addr(sbi, &new_ni, NEW_ADDR, false);
	inc_valid_inode_count(sbi);
	// 置脏，等待回写
	set_page_dirty(ipage);
	f2fs_put_page(ipage, 1);
	return 0;
}

// TODO
int f2fs_restore_node_summary(struct f2fs_sb_info *sbi,
			unsigned int segno, struct f2fs_summary_block *sum)
{
	struct f2fs_node *rn;
	struct f2fs_summary *sum_entry;
	block_t addr;
	int i, idx, last_offset, nrpages;

	/* scan the node segment */
	last_offset = sbi->blocks_per_seg;
	addr = START_BLOCK(sbi, segno);
	sum_entry = &sum->entries[0];

	for (i = 0; i < last_offset; i += nrpages, addr += nrpages) {
		nrpages = bio_max_segs(last_offset - i);

		/* readahead node pages */
		f2fs_ra_meta_pages(sbi, addr, nrpages, META_POR, true);

		for (idx = addr; idx < addr + nrpages; idx++) {
			struct page *page = f2fs_get_tmp_page(sbi, idx);

			if (IS_ERR(page))
				return PTR_ERR(page);

			rn = F2FS_NODE(page);
			sum_entry->nid = rn->footer.nid;
			sum_entry->version = 0;
			sum_entry->ofs_in_node = 0;
			sum_entry++;
			f2fs_put_page(page, 1);
		}

		invalidate_mapping_pages(META_MAPPING(sbi), addr,
							addr + nrpages);
	}
	return 0;
}

// 将journal里面的nat_entry cache取下，放到set中，用于一致性。
static void remove_nats_in_journal(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	// TODO：为什么只处理HOT DATA?
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	struct f2fs_journal *journal = curseg->journal;
	int i;

	down_write(&curseg->journal_rwsem);
	for (i = 0; i < nats_in_cursum(journal); i++) {
		struct nat_entry *ne;
		struct f2fs_nat_entry raw_ne;
		nid_t nid = le32_to_cpu(nid_in_journal(journal, i));

		if (f2fs_check_nid_range(sbi, nid))
			continue;

		// 在journal中缓存的nat_entry
		raw_ne = nat_in_journal(journal, i);

		// 如果nat_root中还没有相关的nat_entry cache，则创建一个，并用
		// journal中的缓存进行初始化。
		ne = __lookup_nat_cache(nm_i, nid);
		if (!ne) {
			ne = __alloc_nat_entry(sbi, nid, true);
			__init_nat_entry(nm_i, ne, &raw_ne, true);
		}

		/*
		 * if a free nat in journal has not been used after last
		 * checkpoint, we should remove it from available nids,
		 * since later we will add it again.
		 */
		if (!get_nat_flag(ne, IS_DIRTY) &&
				le32_to_cpu(raw_ne.block_addr) == NULL_ADDR) {
			spin_lock(&nm_i->nid_list_lock);
			nm_i->available_nids--;
			spin_unlock(&nm_i->nid_list_lock);
		}

		// 将nat_entry cache置为dirty，并放到set中
		__set_nat_cache_dirty(nm_i, ne);
	}
	// 将journal的内容清空
	update_nats_in_cursum(journal, -i);
	up_write(&curseg->journal_rwsem);
}

// 将nes插入到集合中，根据entry_cnt的大小进行排序，这是为了尽可能将更多的nat_entry
// 放到journal中。
static void __adjust_nat_entry_set(struct nat_entry_set *nes,
						struct list_head *head, int max)
{
	struct nat_entry_set *cur;

	if (nes->entry_cnt >= max)
		goto add_out;

	list_for_each_entry(cur, head, set_list) {
		if (cur->entry_cnt >= nes->entry_cnt) {
			list_add(&nes->set_list, cur->set_list.prev);
			return;
		}
	}
add_out:
	list_add_tail(&nes->set_list, head);
}

// 更新某个nat block的empty或者full标记
static void __update_nat_bits(struct f2fs_nm_info *nm_i, unsigned int nat_ofs,
							unsigned int valid)
{
	if (valid == 0) {
		__set_bit_le(nat_ofs, nm_i->empty_nat_bits);
		__clear_bit_le(nat_ofs, nm_i->full_nat_bits);
		return;
	}

	__clear_bit_le(nat_ofs, nm_i->empty_nat_bits);
	if (valid == NAT_ENTRY_PER_BLOCK)
		__set_bit_le(nat_ofs, nm_i->full_nat_bits);
	else
		__clear_bit_le(nat_ofs, nm_i->full_nat_bits);
}

// 更新单个nat_block的empty和full情况，在flush nat_entry之后调用
static void update_nat_bits(struct f2fs_sb_info *sbi, nid_t start_nid,
						struct page *page)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned int nat_index = start_nid / NAT_ENTRY_PER_BLOCK;
	struct f2fs_nat_block *nat_blk = page_address(page);
	int valid = 0;
	int i = 0;

	if (!is_set_ckpt_flags(sbi, CP_NAT_BITS_FLAG))
		return;

	if (nat_index == 0) {
		valid = 1;
		i = 1;
	}
	for (; i < NAT_ENTRY_PER_BLOCK; i++) {
		if (le32_to_cpu(nat_blk->entries[i].block_addr) != NULL_ADDR)
			valid++;
	}

	__update_nat_bits(nm_i, nat_index, valid);
}

// 初始化阶段使用？遍历所有nat_blocks，更新empty和full block_bitmap的情况
void f2fs_enable_nat_bits(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned int nat_ofs;

	f2fs_down_read(&nm_i->nat_tree_lock);

	for (nat_ofs = 0; nat_ofs < nm_i->nat_blocks; nat_ofs++) {
		unsigned int valid = 0, nid_ofs = 0;

		/* handle nid zero due to it should never be used */
		// 0号的nid总是不会被使用，这里要跳过
		if (unlikely(nat_ofs == 0)) {
			valid = 1;
			nid_ofs = 1;
		}

		for (; nid_ofs < NAT_ENTRY_PER_BLOCK; nid_ofs++) {
			if (!test_bit_le(nid_ofs,
					nm_i->free_nid_bitmap[nat_ofs]))
				valid++;
		}

		__update_nat_bits(nm_i, nat_ofs, valid);
	}

	f2fs_up_read(&nm_i->nat_tree_lock);
}

static int __flush_nat_entry_set(struct f2fs_sb_info *sbi,
		struct nat_entry_set *set, struct cp_control *cpc)
{
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	struct f2fs_journal *journal = curseg->journal;
	nid_t start_nid = set->set * NAT_ENTRY_PER_BLOCK;
	bool to_journal = true;
	struct f2fs_nat_block *nat_blk;
	struct nat_entry *ne, *cur;
	struct page *page = NULL;

	/*
	 * there are two steps to flush nat entries:
	 * #1, flush nat entries to journal in current hot data summary block.
	 * #2, flush nat entries to nat page.
	 */
	if ((cpc->reason & CP_UMOUNT) ||
		!__has_cursum_space(journal, set->entry_cnt, NAT_JOURNAL))
		to_journal = false;

	if (to_journal) {
		down_write(&curseg->journal_rwsem);
	} else {
		page = get_next_nat_page(sbi, start_nid);
		if (IS_ERR(page))
			return PTR_ERR(page);

		nat_blk = page_address(page);
		f2fs_bug_on(sbi, !nat_blk);
	}

	/* flush dirty nats in nat entry set */
	list_for_each_entry_safe(ne, cur, &set->entry_list, list) {
		struct f2fs_nat_entry *raw_ne;
		nid_t nid = nat_get_nid(ne);
		int offset;

		f2fs_bug_on(sbi, nat_get_blkaddr(ne) == NEW_ADDR);

		if (to_journal) {
			offset = f2fs_lookup_journal_in_cursum(journal,
							NAT_JOURNAL, nid, 1);
			f2fs_bug_on(sbi, offset < 0);
			raw_ne = &nat_in_journal(journal, offset);
			nid_in_journal(journal, offset) = cpu_to_le32(nid);
		} else {
			raw_ne = &nat_blk->entries[nid - start_nid];
		}
		raw_nat_from_node_info(raw_ne, &ne->ni);
		nat_reset_flag(ne);
		__clear_nat_cache_dirty(NM_I(sbi), set, ne);
		if (nat_get_blkaddr(ne) == NULL_ADDR) {
			add_free_nid(sbi, nid, false, true);
		} else {
			spin_lock(&NM_I(sbi)->nid_list_lock);
			update_free_nid_bitmap(sbi, nid, false, false);
			spin_unlock(&NM_I(sbi)->nid_list_lock);
		}
	}

	if (to_journal) {
		up_write(&curseg->journal_rwsem);
	} else {
		update_nat_bits(sbi, start_nid, page);
		f2fs_put_page(page, 1);
	}

	/* Allow dirty nats by node block allocation in write_begin */
	if (!set->entry_cnt) {
		radix_tree_delete(&NM_I(sbi)->nat_set_root, set->set);
		kmem_cache_free(nat_entry_set_slab, set);
	}
	return 0;
}

/*
 * This function is called during the checkpointing process.
 */
int f2fs_flush_nat_entries(struct f2fs_sb_info *sbi, struct cp_control *cpc)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	// CP流程下刷nat entry cache借用了hot data的journal
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	struct f2fs_journal *journal = curseg->journal;
	struct nat_entry_set *setvec[SETVEC_SIZE];
	struct nat_entry_set *set, *tmp;
	unsigned int found;
	nid_t set_idx = 0;
	LIST_HEAD(sets);
	int err = 0;

	/*
	 * during unmount, let's flush nat_bits before checking
	 * nat_cnt[DIRTY_NAT].
	 */
	// 如果是umount流程，则先将journal中缓存的nat_entry放入到set中，
	// 用于将nat_entry放如到current->journal或下刷到存储介质
	// TODO：此处用于加快后面的下刷速度？
	if (cpc->reason & CP_UMOUNT) {
		f2fs_down_write(&nm_i->nat_tree_lock);
		remove_nats_in_journal(sbi);
		f2fs_up_write(&nm_i->nat_tree_lock);
	}

	if (!nm_i->nat_cnt[DIRTY_NAT])
		return 0;

	f2fs_down_write(&nm_i->nat_tree_lock);

	/*
	 * if there are no enough space in journal to store dirty nat
	 * entries, remove all entries from journal and merge them
	 * into nat entry set.
	 */
	// 如果是umount流程，就将journal下刷（但前面已经下刷过了？）
	// 如果当前journal没有空间，也会释放journal的空间。
	if (cpc->reason & CP_UMOUNT ||
		!__has_cursum_space(journal,
			nm_i->nat_cnt[DIRTY_NAT], NAT_JOURNAL))
		remove_nats_in_journal(sbi);

	// 遍历nat_set_root，将set中所有nat_entry下刷，这里需要考虑net_entry的合并
	while ((found = __gang_lookup_nat_set(nm_i,
					set_idx, SETVEC_SIZE, setvec))) {
		unsigned idx;

		set_idx = setvec[found - 1]->set + 1;
		for (idx = 0; idx < found; idx++)
			__adjust_nat_entry_set(setvec[idx], &sets,
						MAX_NAT_JENTRIES(journal));
	}

	/* flush dirty nats in nat entry set */
	// 将nat_entry_set放到journal或者下刷到存储介质。
	list_for_each_entry_safe(set, tmp, &sets, set_list) {
		err = __flush_nat_entry_set(sbi, set, cpc);
		if (err)
			break;
	}

	f2fs_up_write(&nm_i->nat_tree_lock);
	/* Allow dirty nats by node block allocation in write_begin */

	return err;
}

static int __get_nat_bitmaps(struct f2fs_sb_info *sbi)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned int nat_bits_bytes = nm_i->nat_blocks / BITS_PER_BYTE;
	unsigned int i;
	__u64 cp_ver = cur_cp_version(ckpt);
	block_t nat_bits_addr;

	nm_i->nat_bits_blocks = F2FS_BLK_ALIGN((nat_bits_bytes << 1) + 8);
	nm_i->nat_bits = f2fs_kvzalloc(sbi,
			nm_i->nat_bits_blocks << F2FS_BLKSIZE_BITS, GFP_KERNEL);
	if (!nm_i->nat_bits)
		return -ENOMEM;

	nm_i->full_nat_bits = nm_i->nat_bits + 8;
	nm_i->empty_nat_bits = nm_i->full_nat_bits + nat_bits_bytes;

	if (!is_set_ckpt_flags(sbi, CP_NAT_BITS_FLAG))
		return 0;

	nat_bits_addr = __start_cp_addr(sbi) + sbi->blocks_per_seg -
						nm_i->nat_bits_blocks;
	for (i = 0; i < nm_i->nat_bits_blocks; i++) {
		struct page *page;

		page = f2fs_get_meta_page(sbi, nat_bits_addr++);
		if (IS_ERR(page))
			return PTR_ERR(page);

		memcpy(nm_i->nat_bits + (i << F2FS_BLKSIZE_BITS),
					page_address(page), F2FS_BLKSIZE);
		f2fs_put_page(page, 1);
	}

	cp_ver |= (cur_cp_crc(ckpt) << 32);
	if (cpu_to_le64(cp_ver) != *(__le64 *)nm_i->nat_bits) {
		clear_ckpt_flags(sbi, CP_NAT_BITS_FLAG);
		f2fs_notice(sbi, "Disable nat_bits due to incorrect cp_ver (%llu, %llu)",
			cp_ver, le64_to_cpu(*(__le64 *)nm_i->nat_bits));
		return 0;
	}

	f2fs_notice(sbi, "Found nat_bits in checkpoint");
	return 0;
}

static inline void load_free_nid_bitmap(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned int i = 0;
	nid_t nid, last_nid;

	if (!is_set_ckpt_flags(sbi, CP_NAT_BITS_FLAG))
		return;

	for (i = 0; i < nm_i->nat_blocks; i++) {
		i = find_next_bit_le(nm_i->empty_nat_bits, nm_i->nat_blocks, i);
		if (i >= nm_i->nat_blocks)
			break;

		__set_bit_le(i, nm_i->nat_block_bitmap);

		nid = i * NAT_ENTRY_PER_BLOCK;
		last_nid = nid + NAT_ENTRY_PER_BLOCK;

		spin_lock(&NM_I(sbi)->nid_list_lock);
		for (; nid < last_nid; nid++)
			update_free_nid_bitmap(sbi, nid, true, true);
		spin_unlock(&NM_I(sbi)->nid_list_lock);
	}

	for (i = 0; i < nm_i->nat_blocks; i++) {
		i = find_next_bit_le(nm_i->full_nat_bits, nm_i->nat_blocks, i);
		if (i >= nm_i->nat_blocks)
			break;

		__set_bit_le(i, nm_i->nat_block_bitmap);
	}
}

// 初始化node的管理信息
static int init_node_manager(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *sb_raw = F2FS_RAW_SUPER(sbi);
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned char *version_bitmap;
	unsigned int nat_segs;
	int err;

	// 初始化NAT区域的开始block地址，在mkfs.f2fs的时候已经确定下来，这里
	// 只是将super block中的信息存放到内存。
	nm_i->nat_blkaddr = le32_to_cpu(sb_raw->nat_blkaddr);

	/* segment_count_nat includes pair segment so divide to 2. */
	// NTA区域所占的segment(2M)数量，由于NAT区域有备份，所以需要除以2
	nat_segs = le32_to_cpu(sb_raw->segment_count_nat) >> 1;
	// 一个NAT区域的block数量
	nm_i->nat_blocks = nat_segs << le32_to_cpu(sb_raw->log_blocks_per_seg);
	// 一个block最多能管理NAT_ENTRY_PER_BLOCK(819)个node。
	nm_i->max_nid = NAT_ENTRY_PER_BLOCK * nm_i->nat_blocks;

	/* not used nids: 0, node, meta, (and root counted as valid node) */
	// 计算系统中还能使用的block数量，total_valid_node_count是系统上次挂载已经使用的block数量
	// 其中0、1、2号的block被系统保留。
	nm_i->available_nids = nm_i->max_nid - sbi->total_valid_node_count -
						F2FS_RESERVED_NODE_NUM;
	// 空闲block又被分为FREE和PREALLOC，此处暂时初始化成0,后续遍历free node后才真正计算其值。
	nm_i->nid_cnt[FREE_NID] = 0;
	nm_i->nid_cnt[PREALLOC_NID] = 0;

	// TODO：
	nm_i->ram_thresh = DEF_RAM_THRESHOLD;
	nm_i->ra_nid_pages = DEF_RA_NID_PAGES;
	nm_i->dirty_nats_ratio = DEF_DIRTY_NAT_RATIO_THRESHOLD;
	nm_i->max_rf_node_blocks = DEF_RF_NODE_BLOCKS;

	// 通过红黑树(?)来快速查找free_nid，通过空间换时间
	INIT_RADIX_TREE(&nm_i->free_nid_root, GFP_ATOMIC);
	// 通过链表管理free node，不包括prealloc node。与free_nid_root包含
	// 的node重复。
	INIT_LIST_HEAD(&nm_i->free_nid_list);
	// 通过红黑树（？）管理所有nat entry
	INIT_RADIX_TREE(&nm_i->nat_root, GFP_NOIO);
	// TODO:
	INIT_RADIX_TREE(&nm_i->nat_set_root, GFP_NOIO);
	// 记录所有nat entry的链表
	INIT_LIST_HEAD(&nm_i->nat_entries);
	spin_lock_init(&nm_i->nat_list_lock);

	mutex_init(&nm_i->build_lock);
	spin_lock_init(&nm_i->nid_list_lock);
	init_f2fs_rwsem(&nm_i->nat_tree_lock);

	// 上一次umount前的下一个将要被扫描的node id。
	nm_i->next_scan_nid = le32_to_cpu(sbi->ckpt->next_free_nid);
	nm_i->bitmap_size = __bitmap_size(sbi, NAT_BITMAP);
	version_bitmap = __bitmap_ptr(sbi, NAT_BITMAP);
	nm_i->nat_bitmap = kmemdup(version_bitmap, nm_i->bitmap_size,
					GFP_KERNEL);
	if (!nm_i->nat_bitmap)
		return -ENOMEM;

	err = __get_nat_bitmaps(sbi);
	if (err)
		return err;

#ifdef CONFIG_F2FS_CHECK_FS
	nm_i->nat_bitmap_mir = kmemdup(version_bitmap, nm_i->bitmap_size,
					GFP_KERNEL);
	if (!nm_i->nat_bitmap_mir)
		return -ENOMEM;
#endif

	return 0;
}

static int init_free_nid_cache(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	int i;

	// free_nid_bitmap是一个二维数组，每个bit对应的是一个node block是否被使用
	nm_i->free_nid_bitmap =
		f2fs_kvzalloc(sbi, array_size(sizeof(unsigned char *),
					      nm_i->nat_blocks),
			      GFP_KERNEL);
	if (!nm_i->free_nid_bitmap)
		return -ENOMEM;

	for (i = 0; i < nm_i->nat_blocks; i++) {
		nm_i->free_nid_bitmap[i] = f2fs_kvzalloc(sbi,
			f2fs_bitmap_size(NAT_ENTRY_PER_BLOCK), GFP_KERNEL);
		if (!nm_i->free_nid_bitmap[i])
			return -ENOMEM;
	}

	// 每个bit对应NAT区域每个block是否被使用
	nm_i->nat_block_bitmap = f2fs_kvzalloc(sbi, nm_i->nat_blocks / 8,
								GFP_KERNEL);
	if (!nm_i->nat_block_bitmap)
		return -ENOMEM;

	// 记录每个nat_block空闲的nat entry数量
	nm_i->free_nid_count =
		f2fs_kvzalloc(sbi, array_size(sizeof(unsigned short),
					      nm_i->nat_blocks),
			      GFP_KERNEL);
	if (!nm_i->free_nid_count)
		return -ENOMEM;
	return 0;
}

// 创建node的管理结构，也即f2fs_nm_info
int f2fs_build_node_manager(struct f2fs_sb_info *sbi)
{
	int err;

	// 分配f2fs_nm_info的空间
	sbi->nm_info = f2fs_kzalloc(sbi, sizeof(struct f2fs_nm_info),
							GFP_KERNEL);
	if (!sbi->nm_info)
		return -ENOMEM;

	// 初始化f2fs_nm_info的信息
	err = init_node_manager(sbi);
	if (err)
		return err;

	err = init_free_nid_cache(sbi);
	if (err)
		return err;

	/* load free nid status from nat_bits table */
	load_free_nid_bitmap(sbi);

	return f2fs_build_free_nids(sbi, true, true);
}

// 销毁node的管理结构
void f2fs_destroy_node_manager(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *i, *next_i;
	struct nat_entry *natvec[NATVEC_SIZE];
	struct nat_entry_set *setvec[SETVEC_SIZE];
	nid_t nid = 0;
	unsigned int found;

	if (!nm_i)
		return;

	/* destroy free nid list */
	spin_lock(&nm_i->nid_list_lock);
	list_for_each_entry_safe(i, next_i, &nm_i->free_nid_list, list) {
		__remove_free_nid(sbi, i, FREE_NID);
		spin_unlock(&nm_i->nid_list_lock);
		kmem_cache_free(free_nid_slab, i);
		spin_lock(&nm_i->nid_list_lock);
	}
	f2fs_bug_on(sbi, nm_i->nid_cnt[FREE_NID]);
	f2fs_bug_on(sbi, nm_i->nid_cnt[PREALLOC_NID]);
	f2fs_bug_on(sbi, !list_empty(&nm_i->free_nid_list));
	spin_unlock(&nm_i->nid_list_lock);

	/* destroy nat cache */
	f2fs_down_write(&nm_i->nat_tree_lock);
	while ((found = __gang_lookup_nat_cache(nm_i,
					nid, NATVEC_SIZE, natvec))) {
		unsigned idx;

		nid = nat_get_nid(natvec[found - 1]) + 1;
		for (idx = 0; idx < found; idx++) {
			spin_lock(&nm_i->nat_list_lock);
			list_del(&natvec[idx]->list);
			spin_unlock(&nm_i->nat_list_lock);

			__del_from_nat_cache(nm_i, natvec[idx]);
		}
	}
	f2fs_bug_on(sbi, nm_i->nat_cnt[TOTAL_NAT]);

	/* destroy nat set cache */
	nid = 0;
	while ((found = __gang_lookup_nat_set(nm_i,
					nid, SETVEC_SIZE, setvec))) {
		unsigned idx;

		nid = setvec[found - 1]->set + 1;
		for (idx = 0; idx < found; idx++) {
			/* entry_cnt is not zero, when cp_error was occurred */
			f2fs_bug_on(sbi, !list_empty(&setvec[idx]->entry_list));
			radix_tree_delete(&nm_i->nat_set_root, setvec[idx]->set);
			kmem_cache_free(nat_entry_set_slab, setvec[idx]);
		}
	}
	f2fs_up_write(&nm_i->nat_tree_lock);

	kvfree(nm_i->nat_block_bitmap);
	if (nm_i->free_nid_bitmap) {
		int i;

		for (i = 0; i < nm_i->nat_blocks; i++)
			kvfree(nm_i->free_nid_bitmap[i]);
		kvfree(nm_i->free_nid_bitmap);
	}
	kvfree(nm_i->free_nid_count);

	kvfree(nm_i->nat_bitmap);
	kvfree(nm_i->nat_bits);
#ifdef CONFIG_F2FS_CHECK_FS
	kvfree(nm_i->nat_bitmap_mir);
#endif
	sbi->nm_info = NULL;
	kfree(nm_i);
}

// 创建f2fs管理node时需要的内存分配器
int __init f2fs_create_node_manager_caches(void)
{
	// nat_entry内存分配器，用于在内存中缓存一个nat_entry
	nat_entry_slab = f2fs_kmem_cache_create("f2fs_nat_entry",
			sizeof(struct nat_entry));
	if (!nat_entry_slab)
		goto fail;

	// node id的内存分配器，插入到全局node管理结构free_nid_list
	free_nid_slab = f2fs_kmem_cache_create("f2fs_free_nid",
			sizeof(struct free_nid));
	if (!free_nid_slab)
		goto destroy_nat_entry;

	// TODO:
	nat_entry_set_slab = f2fs_kmem_cache_create("f2fs_nat_entry_set",
			sizeof(struct nat_entry_set));
	if (!nat_entry_set_slab)
		goto destroy_free_nid;

	// fsync流程中将某次提交的node page放到sbi的fsync_node_list链表中，用于一次性等待
	// 所有page回写完成。
	fsync_node_entry_slab = f2fs_kmem_cache_create("f2fs_fsync_node_entry",
			sizeof(struct fsync_node_entry));
	if (!fsync_node_entry_slab)
		goto destroy_nat_entry_set;
	return 0;

destroy_nat_entry_set:
	kmem_cache_destroy(nat_entry_set_slab);
destroy_free_nid:
	kmem_cache_destroy(free_nid_slab);
destroy_nat_entry:
	kmem_cache_destroy(nat_entry_slab);
fail:
	return -ENOMEM;
}

// 销毁内存管理器，在初始化失败或f2fs.ko卸载时调用
void f2fs_destroy_node_manager_caches(void)
{
	kmem_cache_destroy(fsync_node_entry_slab);
	kmem_cache_destroy(nat_entry_set_slab);
	kmem_cache_destroy(free_nid_slab);
	kmem_cache_destroy(nat_entry_slab);
}
