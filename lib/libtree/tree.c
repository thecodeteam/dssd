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

/*
 * Left-Leaning Red-Black Trees, first described by Sedgewick in 2008.
 * I won't recapitulate the theory here; it's all available on Google.
 *
 * This differs from Sedgewick in a few important ways:
 *
 * (1) The tree code never allocates or frees memory.  Tree nodes are
 *     always embedded in whatever data structure is being sorted.
 *     When you create a tree, you specify the offset of a tree_node_t
 *     (which should be treated as opaque) within your data structure.
 *
 * (2) The tree_node_t is just two words: left and right children,
 *     with the node color (red or black) encoded in the low bit of
 *     the right pointer.  These could be further reduced to id32
 *     (actually, id31) should the need arise by passing the id32
 *     base address and structure size to tree_init(), and using this
 *     in node_left() and node_right() to rehydrate the pointers.
 *
 * (3) This code copes with attempts to insert already-existing things,
 *     delete non-existing things, and provides a number of useful
 *     services (described below) beyond the basic lookup/insert/delete.
 *
 * (4) There were a couple of bugs in the paper and slides, fixed here.
 *
 * (5) This code includes a comprehensive validity test (tree_test.c).
 *     Analysis with gcov indicates that every line of code is tested.
 *
 * Locking is up to the client.  Some lock must protect the tree if there is
 * multi-threaded access.  Clients typically hold some client-level lock when
 * calling tree routines anyway, so for efficiency, there is no locking here.
 *
 * The public interfaces are as follows:
 *
 * tree_init(t, cmp(), off)	initialize a tree; cmp() compares nodes
 * tree_fini(t)			finish using a tree; must be empty
 * tree_move(src, dst)		move src to dst and clear src
 * tree_min(t)			return smallest node
 * tree_max(t)			return largest node
 * tree_root(t)			return root of the tree
 * tree_lookup(t, n)		return node matching n, or NULL
 * tree_prev(t, n)		return node before n, NULL if none
 * tree_next(t, n)		return node after n, NULL if none
 * tree_locate(t, n, **p, **n)	lookup n and set *p = prev, *n = next
 * tree_insert(t, n)		insert node into the tree; must succeed
 * tree_try_insert(t, n)	try; NULL on success, colliding node on failure
 * tree_delete_min(t)		delete and return smallest node
 * tree_delete_max(t)		delete and return largest node
 * tree_delete(t, n)		delete node from the tree; must succeed
 * tree_try_delete(t, n)	try; deleted node on success, NULL on failure
 * tree_teardown(t, destructor, private) delete all nodes without rebalance cost
 * tree_empty(t)		boolean indicating whether tree is empty
 * tree_nodes(t)		number of nodes in the tree
 * tree_walk(t, func, private)	walk tree in order calling func(node, private)
 * tree_valid(t)		verify that entire tree is self-consistent
 * tree_draw(t, flat)		SVG drawing of t, optionally with red links flat
 *
 * For performance-critical, lookup-intensive workloads, the performance of
 * lookup can be improved by using an inline version; see TREE_LOOKUP_FUNC
 * in tree.h, and the example in tree_test.c.
 */

#include <tree.h>
#include <stdio.h>
#include <assert.h>

#define	ASSERT	assert

/*
 * ============================================================================
 * Node to containing data structure conversion and comparison
 * ============================================================================
 */
static inline void *
__attribute__((always_inline))
__attribute__((pure))
node_to_data(const tree_t *t, const tree_node_t *n)
{
	return ((void *)((uintptr_t)n - t->t_off));
}

static inline tree_node_t *
__attribute__((always_inline))
__attribute__((pure))
node_from_data(const tree_t *t, const void *data)
{
	return ((tree_node_t *)((uintptr_t)data + t->t_off));
}

static inline int
__attribute__((always_inline))
__attribute__((pure))
node_compare(const tree_t *t, const tree_node_t *n1, const tree_node_t *n2)
{
	return (t->t_cmp(node_to_data(t, n1), node_to_data(t, n2)));
}

/*
 * ============================================================================
 * Node accessor functions that directly maniuplate encoded node fields
 * ============================================================================
 */
static inline tree_node_t *
__attribute__((always_inline))
__attribute__((pure))
node_left(const tree_node_t *n)
{
	return ((tree_node_t *)(n->n_left));
}

static inline tree_node_t *
__attribute__((always_inline))
__attribute__((pure))
node_right(const tree_node_t *n)
{
	return ((tree_node_t *)(n->n_right_red & TREE_NODE_RIGHT));
}

static inline int
__attribute__((always_inline))
__attribute__((pure))
node_red(const tree_node_t *n)
{
	return (n == NULL ? 0 : n->n_right_red & TREE_NODE_RED);
}

static inline void
__attribute__((always_inline))
node_set_left(tree_node_t *n, const tree_node_t *left)
{
	n->n_left = (uintptr_t)left;
}

static inline void
__attribute__((always_inline))
node_set_right(tree_node_t *n, const tree_node_t *right)
{
	n->n_right_red = (n->n_right_red & TREE_NODE_RED) | (uintptr_t)right;
}

static inline void
__attribute__((always_inline))
node_set_red(tree_node_t *n, int red)
{
	n->n_right_red = (n->n_right_red & TREE_NODE_RIGHT) | red;
}

static inline void
__attribute__((always_inline))
node_flip_red(tree_node_t *n)
{
	n->n_right_red ^= TREE_NODE_RED;
}

static inline tree_node_t *
__attribute__((always_inline))
node_init(tree_node_t *n)
{
	n->n_left = 0;
	n->n_right_red = TREE_NODE_RED;

	return (n);
}

/*
 * ============================================================================
 * Node rotations and operations to maintain tree balance and link colors
 * ============================================================================
 */
static inline tree_node_t *
__attribute__((always_inline))
node_rotate_left(tree_node_t *n)
{
	tree_node_t *r = node_right(n);

	node_set_right(n, node_left(r));
	node_set_left(r, n);
	node_set_red(r, node_red(n));
	node_set_red(n, TREE_NODE_RED);

	return (r);
}

static inline tree_node_t *
__attribute__((always_inline))
node_rotate_right(tree_node_t *n)
{
	tree_node_t *l = node_left(n);

	node_set_left(n, node_right(l));
	node_set_right(l, n);
	node_set_red(l, node_red(n));
	node_set_red(n, TREE_NODE_RED);

	return (l);
}

static inline void
__attribute__((always_inline))
node_color_flip(tree_node_t *n)
{
	node_flip_red(n);
	node_flip_red(node_left(n));
	node_flip_red(node_right(n));
}

static inline tree_node_t *
__attribute__((always_inline))
node_move_red_left(tree_node_t *n)
{
	if (!node_red(node_left(n)) &&
	    !node_red(node_left(node_left(n)))) {
		node_color_flip(n);
		if (node_red(node_left(node_right(n)))) {
			node_set_right(n, node_rotate_right(node_right(n)));
			n = node_rotate_left(n);
			node_color_flip(n);
		}
	}
	return (n);
}

static inline tree_node_t *
__attribute__((always_inline))
node_move_red_right(tree_node_t *n)
{
	if (!node_red(node_right(n)) &&
	    !node_red(node_left(node_right(n)))) {
		node_color_flip(n);
		if (node_red(node_left(node_left(n)))) {
			n = node_rotate_right(n);
			node_color_flip(n);
		}
	}
	return (n);
}

static inline tree_node_t *
__attribute__((always_inline))
node_fix_up(tree_node_t *n)
{
	if (node_red(node_right(n)))
		n = node_rotate_left(n);

	if (node_red(node_left(n)) && node_red(node_left(node_left(n))))
		n = node_rotate_right(n);

	if (node_red(node_left(n)) && node_red(node_right(n)))
		node_color_flip(n);

	return (n);
}

/*
 * ============================================================================
 * Node operations on whole subtrees
 * ============================================================================
 */
static inline tree_node_t *
__attribute__((always_inline))
node_min(tree_node_t *n)
{
	while (node_left(n) != NULL)
		n = node_left(n);

	return (n);
}

static inline tree_node_t *
__attribute__((always_inline))
node_max(tree_node_t *n)
{
	while (node_right(n) != NULL)
		n = node_right(n);

	return (n);
}

static inline tree_node_t *
__attribute__((always_inline))
node_locate(const tree_t *t, tree_node_t *n, const tree_node_t *x,
    tree_node_t **prev, tree_node_t **next)
{
	while (n != NULL) {
		int cmp = node_compare(t, x, n);

		if (cmp == 0) {
			if (prev != NULL && node_left(n) != NULL)
				*prev = node_max(node_left(n));
			if (next != NULL && node_right(n) != NULL)
				*next = node_min(node_right(n));
			return (n);
		}
		if (cmp < 0) {
			if (next != NULL)
				*next = n;
			n = node_left(n);
		} else {
			if (prev != NULL)
				*prev = n;
			n = node_right(n);
		}
	}

	return (node_from_data(t, NULL));
}

static tree_node_t *
node_insert(const tree_t *t, tree_node_t *n, tree_node_t *x, tree_node_t **f)
{
	int cmp;

	if (n == NULL)
		return (node_init(x));

	cmp = node_compare(t, x, n);

	if (cmp < 0) {
		node_set_left(n, node_insert(t, node_left(n), x, f));
	} else if (cmp > 0) {
		node_set_right(n, node_insert(t, node_right(n), x, f));
	} else {
		*f = n;		// found: equal key or node already in tree
	}

	return (node_fix_up(n));
}

static tree_node_t *
node_delete_min(const tree_t *t, tree_node_t *n, tree_node_t **f)
{
	if (node_left(n) == NULL) {
		*f = n;		// found the min
		return (NULL);
	}

	n = node_move_red_left(n);

	node_set_left(n, node_delete_min(t, node_left(n), f));

	return (node_fix_up(n));
}

static tree_node_t *
node_delete_max(const tree_t *t, tree_node_t *n, tree_node_t **f)
{
	if (node_red(node_left(n)))
		n = node_rotate_right(n);

	if (node_right(n) == NULL) {
		*f = n;		// found the max
		return (NULL);
	}

	n = node_move_red_right(n);

	node_set_right(n, node_delete_max(t, node_right(n), f));

	return (node_fix_up(n));
}

static tree_node_t *
node_delete(const tree_t *t, tree_node_t *n, tree_node_t *x, tree_node_t **f)
{
	int cmp = node_compare(t, x, n);

	if (cmp < 0) {
		if (node_left(n) == NULL)
			return (node_fix_up(n));
		n = node_move_red_left(n);
		node_set_left(n, node_delete(t, node_left(n), x, f));
	} else {
		if (node_red(node_left(n)))
			n = node_rotate_right(n);
		if (node_right(n) == NULL) {
			if (cmp != 0)
				return (node_fix_up(n));
			*f = n;		// found node n matching x
			return (NULL);
		}
		n = node_move_red_right(n);
		if (node_compare(t, x, n) == 0) {
			node_set_right(n, node_delete_min(t, node_right(n), f));
			x = *f;		// x = next node after n
			*f = n;		// indicate node n found
			*x = *n;	// next takes n's place in the tree
			n = x;		// return next instead of n
		} else {
			node_set_right(n, node_delete(t, node_right(n), x, f));
		}
	}

	return (node_fix_up(n));
}

static size_t
node_nodes(const tree_node_t *n)
{
	return (n == NULL ? 0 :
	    1 + node_nodes(node_left(n)) + node_nodes(node_right(n)));
}

static int
node_black_height(const tree_node_t *n)
{
	return (n == NULL ? 0 : 1 + node_black_height(node_right(n)));
}

static void
node_walk(const tree_t *t, const tree_node_t *n, tree_walk_f *func, void *arg)
{
	if (n != NULL) {
		node_walk(t, node_left(n), func, arg);
		func(node_to_data(t, n), arg);
		node_walk(t, node_right(n), func, arg);
	}
}

static int
node_valid(const tree_t *t, const tree_node_t *n,
    const tree_node_t *min, const tree_node_t *max, int black_height)
{
	/*
	 * The tree should be perfectly black-balanced: every path from
	 * the root to a leaf should have the same number of black links.
	 */
	if (n == NULL)
		return (black_height == 0);

	if (!node_red(n))
		black_height--;

	/*
	 * The bottom-up 2-3 left-leaning red-black tree invariant is that
	 * there are no red right links, and no consecutive red left links.
	 */
	if (node_red(node_right(n)))
		return (0);

	if (node_red(n) && node_red(node_left(n)))
		return (0);

	/*
	 * The tree should be ordered, so that node n is in (min, max).
	 * Everything node in n's left subtree should be in (min, n).
	 * Everything node in n's right subtree should be in (n, max).
	 */
	if (min != NULL && node_compare(t, min, n) >= 0)
		return (0);

	if (max != NULL && node_compare(t, n, max) >= 0)
		return (0);

	return (node_valid(t, node_left(n), min, n, black_height) &&
	    node_valid(t, node_right(n), n, max, black_height));
}

static void
node_draw(const tree_node_t *n, double w, double h, double d, int f,
    double x, double y, double px, double py)
{
	if (n == NULL)
		return;

	if (f && node_red(n))
		y = py;

	node_draw(node_left(n),  w / 2, h, d * 0.9, f, x - w / 2, y + h, x, y);
	node_draw(node_right(n), w / 2, h, d * 0.9, f, x + w / 2, y + h, x, y);

	printf("<line x1='%f' y1='%f' x2='%f' y2='%f' "
	    "stroke='%s' stroke-width='%f' stroke-linecap='round'/>\n",
	    x, y, px, py, node_red(n) ? "red" : "black", d);
}

static inline tree_node_t *
__attribute__((always_inline))
node_root(tree_t *t, tree_node_t *root)
{
	if (root != NULL)
		node_set_red(root, TREE_NODE_BLACK);

	return (root);
}

/*
 * ============================================================================
 * Tree operations:  public interfaces
 * ============================================================================
 */
void
tree_init(tree_t *t, tree_compare_f *cmp, size_t off)
{
	t->t_root = NULL;
	t->t_cmp = cmp;
	t->t_off = off;
}

void
tree_fini(tree_t *t)
{
	ASSERT(t->t_root == NULL);
	t->t_root = (tree_node_t *)UINTPTR_MAX;
}

void *
tree_min(const tree_t *t)
{
	tree_node_t *root = t->t_root;

	return (root == NULL ? NULL : node_to_data(t, node_min(root)));
}

void *
tree_max(const tree_t *t)
{
	tree_node_t *root = t->t_root;

	return (root == NULL ? NULL : node_to_data(t, node_max(root)));
}

void *
tree_root(const tree_t *t)
{
	tree_node_t *root = t->t_root;

	return (root == NULL ? NULL : node_to_data(t, root));
}

void *
tree_lookup(const tree_t *t, const void *data)
{
	tree_node_t *n = node_from_data(t, data);

	n = node_locate(t, t->t_root, n, NULL, NULL);

	return (node_to_data(t, n));
}

void *
tree_prev(const tree_t *t, const void *data)
{
	tree_node_t *n = node_from_data(t, data);
	tree_node_t *n_prev = node_from_data(t, NULL);

	(void) node_locate(t, t->t_root, n, &n_prev, NULL);

	return (node_to_data(t, n_prev));
}

void *
tree_next(const tree_t *t, const void *data)
{
	tree_node_t *n = node_from_data(t, data);
	tree_node_t *n_next = node_from_data(t, NULL);

	(void) node_locate(t, t->t_root, n, NULL, &n_next);

	return (node_to_data(t, n_next));
}

void *
tree_locate(const tree_t *t, const void *data, void **prev, void **next)
{
	tree_node_t *n = node_from_data(t, data);
	tree_node_t *n_prev = node_from_data(t, NULL);
	tree_node_t *n_next = node_from_data(t, NULL);

	n = node_locate(t, t->t_root, n, &n_prev, &n_next);

	*prev = node_to_data(t, n_prev);
	*next = node_to_data(t, n_next);

	return (node_to_data(t, n));
}

void *
tree_try_insert(tree_t *t, void *data)
{
	tree_node_t *n = node_from_data(t, data);
	tree_node_t *f = node_from_data(t, NULL);

	t->t_root = node_root(t, node_insert(t, t->t_root, n, &f));

	return (node_to_data(t, f));
}

void
tree_insert(tree_t *t, void *data)
{
	void *f = tree_try_insert(t, data);

	ASSERT(f == NULL);
}

void *
tree_delete_min(tree_t *t)
{
	tree_node_t *f = node_from_data(t, NULL);

	if (t->t_root != NULL)
		t->t_root = node_root(t, node_delete_min(t, t->t_root, &f));

	return (node_to_data(t, f));
}

void *
tree_delete_max(tree_t *t)
{
	tree_node_t *f = node_from_data(t, NULL);

	if (t->t_root != NULL)
		t->t_root = node_root(t, node_delete_max(t, t->t_root, &f));

	return (node_to_data(t, f));
}

void *
tree_try_delete(tree_t *t, void *data)
{
	tree_node_t *n = node_from_data(t, data);
	tree_node_t *f = node_from_data(t, NULL);

	if (t->t_root != NULL)
		t->t_root = node_root(t, node_delete(t, t->t_root, n, &f));

	return (node_to_data(t, f));
}

void
tree_delete(tree_t *t, void *data)
{
	void *f = tree_try_delete(t, data);

	ASSERT(f == data);
}

int
tree_empty(const tree_t *t)
{
	return (t->t_root == NULL);
}

size_t
tree_nodes(const tree_t *t)
{
	return (node_nodes(t->t_root));
}

void
tree_walk(const tree_t *t, tree_walk_f *func, void *private)
{
	node_walk(t, t->t_root, func, private);
}

int
tree_valid(const tree_t *t)
{
	const tree_node_t *root = t->t_root;

	return (node_valid(t, root, NULL, NULL, node_black_height(root)));
}

void
tree_draw(const tree_t *t, int flat)
{
	double h = 1.5 / ((1.0 + !flat) * node_black_height(t->t_root) + 0.01);

	printf("<svg width='100%%' height='100%%' viewBox='0 0 2 1.5' "
	    "xmlns='http://www.w3.org/2000/svg' version='1.1'>\n");

	node_draw(t->t_root, 0.99, h, h / 20 * (1.0 + !flat), flat,
	    1.0, h / 2, 1.0, h / 3);

	printf("</svg>\n");
}

static void
node_walk_postorder(const tree_t *t, uintptr_t *np, tree_node_t *n,
    tree_walk_f *destructor, void *private)
{
	if (n != NULL) {
		node_walk_postorder(t, &n->n_left, node_left(n),
		    destructor, private);
		node_walk_postorder(t, &n->n_right_red, node_right(n),
		    destructor, private);
		*np = (uintptr_t)NULL;
		destructor(node_to_data(t, n), private);
	}
}

void
tree_teardown(tree_t *t, tree_walk_f *destructor, void *private)
{
	node_walk_postorder(t, (uintptr_t *)&t->t_root, t->t_root,
	    destructor, private);
}

void
tree_move(tree_t *src, tree_t *dst)
{
	tree_init(dst, src->t_cmp, src->t_off);
	dst->t_root = src->t_root;
	src->t_root = NULL;
}