/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include <string.h>

#include "threads/mmu.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
}

void unmapFileFromPage(struct page *page)
{
	struct fileReader *fr = page->file.fr;
	if (pml4_is_dirty(thread_current()->pml4, page->va))
	{
		file_seek(fr->target, fr->offset);
		file_write(fr->target, page->frame->kva, fr->pageReadBytes);
	}
	pml4_set_dirty(thread_current()->pml4, page->va, false);
}

bool mapFileToPage(struct page *page, struct fileReader *fr)
{
	file_seek(fr->target, fr->offset);
	if (file_read(fr->target, page->frame->kva, fr->pageReadBytes) != fr->pageReadBytes)
	{
		palloc_free_page(page->frame->kva);
		return false;
	}
	memset(page->frame->kva + fr->pageReadBytes, 0, fr->pageZeroBytes);
	pml4_set_dirty(thread_current()->pml4, page->va, false);
	return true;
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	file_page->fr = page->uninit.aux;
	return mapFileToPage(page, file_page->fr);
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in(struct page *page, void *kva)
{
	struct file_page *file_page = &page->file;
	return mapFileToPage(page, file_page->fr);
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
	//	여기 쓸 것
	unmapFileFromPage(page);
	pml4_set_accessed(thread_current()->pml4, page->va, false);
	pml4_clear_page(thread_current()->pml4, page->va);
	//	cow 관련 문제 생길지도??
	page->frame = NULL;
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;

	if (page->frame != NULL) {
		unmapFileFromPage(page);
		if (page->cowCntPtr == NULL || *page->cowCntPtr == 0) {
			// palloc_free_page(page->frame->kva);
			// free(page->cowCntPtr);
		} else {
			*page->cowCntPtr--;
		}
		free(page->frame);
	}

	pml4_set_accessed(thread_current()->pml4, page->va, false);
	pml4_clear_page(thread_current()->pml4, page->va);
}

/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset)
{
	void *firstPage = addr;
	struct file *target = file_reopen(file);
	size_t readLength = file_length(target) < length ? file_length(target) : length;
	size_t zeroBytes = PGSIZE - (readLength % PGSIZE);
	while (readLength > 0 || zeroBytes > 0)
	{
		size_t page_read_bytes = readLength < PGSIZE ? readLength : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		//	준용 추가
		struct fileReader *aux = NULL;
		aux = malloc(sizeof(struct fileReader));
		aux->target = target;
		aux->pageReadBytes = page_read_bytes;
		aux->pageZeroBytes = page_zero_bytes;
		aux->offset = offset;
		aux->mappedCnt = (addr == firstPage) ? (readLength + zeroBytes) / PGSIZE : 0;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
											writable, NULL, aux))
		{
			return NULL;
		}

		/* Advance. */
		readLength -= page_read_bytes;
		zeroBytes -= page_zero_bytes;
		addr += PGSIZE;
		//	준용 추가
		offset += page_read_bytes;
	}
	return firstPage;
}

/* Do the munmap */
void do_munmap(void *addr)
{
	struct page *victim = spt_find_page(&thread_current()->spt, addr);
	struct page *victimFile = victim->file.fr->target;
	if (VM_TYPE(victim->operations->type) != VM_FILE || victim->file.fr->mappedCnt == 0)
	{
		return;
	}
	int unmapCnt = victim->file.fr->mappedCnt;
	while (unmapCnt > 0)
	{
		victim = spt_find_page(&thread_current()->spt, addr);
		spt_remove_page(&thread_current()->spt, victim);
		addr += PGSIZE;
		unmapCnt--;
	}
	file_close(victimFile);
}
