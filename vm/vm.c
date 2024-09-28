/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "vm/uninit.h"
//	준용 추가
#include "lib/string.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		//	준용 추가
		struct page *newPage = malloc(sizeof(struct page));
		bool (*initialier)(struct page *, enum vm_type, void *kva);

		switch (VM_TYPE(type))
		{
		case VM_ANON:
			initialier = anon_initializer;
			break;
		case VM_FILE:
			initialier = file_backed_initializer;
			break;
		}

		uninit_new(newPage, upage, init, type, aux, initialier);
		newPage->writable = writable;
		/* TODO: Insert the page into the spt. */
		//	여기도
		if (!spt_insert_page(spt, newPage))
		{
			free(newPage);
			goto err;
		}
		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
// struct page *
// spt_find_page(struct supplemental_page_table *spt, void *va)
// {
// 	struct page *page = NULL;
// 	/* TODO: Fill this function. */
// 	struct hash_elem *elem;
// 	page = malloc(sizeof(struct page));
// 	page->va = pg_round_down(va);
// 	if (elem = hash_find(&spt->table, &page->hash_elem) != NULL)
// 	{
// 		free(page);
// 		page = hash_entry(elem, struct page, hash_elem);
// 	}
// 	else
// 	{
// 		free(page);
// 		page = NULL;
// 	}
// 	return page;
// }

/* Insert PAGE into spt with validation. */
// bool spt_insert_page(struct supplemental_page_table *spt,
// 					 struct page *page)
// {
// 	int succ = false;
// 	/* TODO: Fill this function. */
// 	//	이미 존재하는지 검사하라는데 흠 ..
// 	if (hash_insert(&spt->table, &page->hash_elem) == NULL)
// 	{
// 		succ = true;
// 	}
// 	return succ;
// }

struct page *page_lookup(struct supplemental_page_table *spt, const void *va)
{
	struct page p;
	struct hash_elem *e;
	p.va = va;
	e = hash_find(&spt->table, &p.hash_elem);
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	return page_lookup(spt, va);
}

bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	int succ = false;
	/* TODO: Fill this function. */
	if (hash_insert(&spt->table, &page->hash_elem) == NULL)
		succ = true;
	return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	hash_delete(&spt->table, &page->hash_elem);
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	//	준용 추가
	frame = malloc(sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
	frame->page = NULL;

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr)
{
	uint64_t tempBottom = thread_current()->stkBottom;
	void *newBottom = pg_round_down(addr);
	while (tempBottom != newBottom && tempBottom > USER_STACK - STACK_LIMIT)
	{
		tempBottom -= PGSIZE;
		vm_alloc_page(VM_ANON, tempBottom, true);
		vm_claim_page(tempBottom);
	}
	thread_current()->stkBottom = newBottom;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr,
						 bool user, bool write, bool not_present)
{
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */

	if (is_kernel_vaddr(addr) || (!not_present) || addr == NULL || addr > USER_STACK)
	{
		return false;
	}
	/* TODO: Your code goes here */
	page = spt_find_page(spt, pg_round_down(addr));
	if (page == NULL)
	{
		if (addr > USER_STACK - STACK_LIMIT && addr >= f->rsp - 8)
		{
			vm_stack_growth(addr);
			return true;
		}
		return false;
	}
	if (!page->writable && write)
	{
		return false;
	}
	return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va)
{
	struct page *page = NULL;
	/* TODO: Fill this function */
	//	준용 추가
	page = spt_find_page(&thread_current()->spt, va);

	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	//	준용 추가
	pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);

	//	09 / 21  - 여기 하던중 [swap 관련 함수가 bool 반환형을 갖지만 아직 완성이 안 됨 ...]
	return swap_in(page, frame->kva);
}

//	준용 추가
bool page_less(const struct hash_elem *a_,
			   const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);

	return a->va < b->va;
}

/* Returns a hash value for page p. */
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt)
{
	//	준용 추가
	hash_init(&spt->table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
								  struct supplemental_page_table *src)
{
	struct hash_iterator hashIter;
	bool succ = false;

	hash_first(&hashIter, &src->table);

	while (hash_next(&hashIter))
	{
		struct page *source = hash_entry(hash_cur(&hashIter), struct page, hash_elem);

		if (VM_TYPE(source->operations->type) == VM_UNINIT)
		{
			if (!vm_alloc_page_with_initializer(page_get_type(source), source->va, source->writable, source->uninit.init, source->uninit.aux))
			{
				goto err;
			}
			continue;
		}

		if (!vm_alloc_page(VM_TYPE(source->operations->type), source->va, source->writable))
			goto err;
		struct page *destination = spt_find_page(dst, source->va);
		if (destination == NULL)
			goto err;
		if (!vm_do_claim_page(destination))
			goto err;
		memcpy(destination->frame->kva, source->frame->kva, PGSIZE);
	}

	succ = true;
err:
	if (!succ)
	{
		supplemental_page_table_kill(dst);
	}
	return succ;
}

void killSptEntry(struct hash_elem *elem, void *aux UNUSED)
{
	struct page *victim = hash_entry(elem, struct page, hash_elem);
	vm_dealloc_page(victim);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	if (!hash_empty(&spt->table))
	{
		hash_clear(&spt->table, (hash_action_func *)killSptEntry);
	}
}
