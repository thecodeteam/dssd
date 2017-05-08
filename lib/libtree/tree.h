/*
 * Copyright 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _TREE_H
#define	_TREE_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	TREE_NODE_BLACK	(0UL)
#define	TREE_NODE_RED	(1UL)
#define	TREE_NODE_RIGHT	(~TREE_NODE_RED)

typedef int tree_compare_f(const void *, const void *);
typedef void tree_walk_f(void *, void *);

typedef struct tree_node {
	uintptr_t n_left;
	uintptr_t n_right_red;
} tree_node_t;

typedef struct tree {
	tree_node_t *t_root;
	tree_compare_f *t_cmp;
	size_t t_off;
} tree_t;

/*
 * Inline-able lookup.  lookf should be declared in the same file as cmpf
 * so that the comparison can be inlined.  See tree_test.c for an example.
 */
#define	TREE_LOOKUP_FUNC(lookf, cmpf, str, field)			\
str *									\
lookf(const tree_t *t, const str *x)					\
{									\
	tree_node_t *n = t->t_root;					\
	while (n != NULL) {						\
		void *f = (uint8_t *)n - offsetof(str, field);		\
		int cmp = cmpf(x, f);					\
		if (cmp == 0)						\
			return (f);					\
		n = (tree_node_t *)(cmp < 0 ?				\
			n->n_left : n->n_right_red & TREE_NODE_RIGHT);	\
	}								\
	return (NULL);							\
}

extern void tree_init(tree_t *t, tree_compare_f *cmp, size_t off);
extern void tree_fini(tree_t *t);
extern void *tree_min(const tree_t *t);
extern void *tree_max(const tree_t *t);
extern void *tree_root(const tree_t *t);
extern void *tree_lookup(const tree_t *t, const void *data);
extern void *tree_prev(const tree_t *t, const void *data);
extern void *tree_next(const tree_t *t, const void *data);
extern void *tree_locate(const tree_t *t, const void *data, void **, void **);
extern void *tree_try_insert(tree_t *t, void *data);
extern void tree_insert(tree_t *t, void *data);
extern void *tree_delete_min(tree_t *t);
extern void *tree_delete_max(tree_t *t);
extern void *tree_try_delete(tree_t *t, void *data);
extern void tree_delete(tree_t *t, void *data);
extern void tree_teardown(tree_t *t, tree_walk_f *destructor, void *private);
extern int tree_empty(const tree_t *t);
extern size_t tree_nodes(const tree_t *t);
extern void tree_walk(const tree_t *t, tree_walk_f *func, void *private);
extern int tree_valid(const tree_t *t);
extern void tree_draw(const tree_t *t, int flat);
extern void tree_test(void);
extern void tree_move(tree_t *, tree_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _TREE_H */
