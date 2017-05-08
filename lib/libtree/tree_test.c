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

#define	ASSERT	assert

#include <alloca.h>
#include <assert.h>
#include <tree.h>
#include <hrtime.h>
#include <rand.h>

/*
 * ============================================================================
 * Tree tests
 * ============================================================================
 */
typedef struct tt_node {
	ssize_t n_value;
	int n_active;
	tree_node_t n_node;
} tt_node_t;

/* ARGSUSED */
static void
tt_node_destroy(void *p, void *arg)
{
	tt_node_t *n = p;
	tt_node_t *walk = arg;
	ASSERT(n->n_active);
	n->n_active = 0;
	walk->n_active--;
}

static int
__attribute__((pure))
tree_test_compare(const void *a1, const void *a2)
{
	const tt_node_t *n1 = a1;
	const tt_node_t *n2 = a2;

	if (n1->n_value < n2->n_value)
		return (-1);
	if (n1->n_value > n2->n_value)
		return (1);
	return (0);
}

static void
tree_test_walk(void *data, void *private)
{
	tt_node_t *n = data;
	tt_node_t *w = private;

	ASSERT(n->n_active);
	ASSERT(n->n_value > w->n_value);

	w->n_value = n->n_value;
	w->n_active++;
}

static inline
TREE_LOOKUP_FUNC(tree_test_lookup, tree_test_compare, tt_node_t, n_node)

static void
tree_test_one(size_t max_nodes, int64_t iters)
{
	tree_t *t = alloca(sizeof (tree_t));
	tt_node_t *na = alloca((max_nodes + 2) * sizeof (tt_node_t));
	tt_node_t *prev, *next, *n, *l, *min, *max, look, walk;
	srand32((int32_t)gethrtime());

	na++;		// array is now bracketed by na[-1] and na[max_nodes]

	for (ssize_t i = -1L; i <= (ssize_t)max_nodes; i++) {
		na[i].n_value = i;
		na[i].n_active = 0;
	}

	tree_init(t, tree_test_compare, offsetof(tt_node_t, n_node));

	ASSERT(tree_nodes(t) == 0);
	ASSERT(tree_delete_min(t) == NULL);
	ASSERT(tree_delete_max(t) == NULL);
	ASSERT(tree_valid(t));

	while (iters-- > 0) {
		n = &na[rand32() % max_nodes];
		look.n_value = n->n_value;

		ASSERT(n - na == n->n_value);

		l = tree_locate(t, &look, (void *)&prev, (void *)&next);

		ASSERT(l == (n->n_active ? n : NULL));
		ASSERT(tree_test_lookup(t, n) == l);
		ASSERT(tree_lookup(t, n) == l);
		ASSERT(tree_lookup(t, &look) == l);
		ASSERT(tree_prev(t, &look) == prev);
		ASSERT(tree_next(t, &look) == next);

		if (prev == NULL)
			prev = &na[-1];
		else
			ASSERT(prev->n_active);

		if (next == NULL)
			next = &na[max_nodes];
		else
			ASSERT(next->n_active);

		ASSERT(prev->n_value < n->n_value);
		ASSERT(next->n_value > n->n_value);

		for (prev++; prev < n; prev++)
			ASSERT(prev->n_active == 0);

		for (next--; next > n; next--)
			ASSERT(next->n_active == 0);

		if (n->n_active) {
			n->n_node.n_right_red ^= TREE_NODE_RED;
			ASSERT(!tree_valid(t));
			n->n_node.n_right_red ^= TREE_NODE_RED;
			ASSERT(tree_valid(t));
			ASSERT(tree_try_insert(t, n) == n);
			ASSERT(tree_valid(t));
			ASSERT(tree_try_insert(t, &look) == n);
			ASSERT(tree_valid(t));
			ASSERT(tree_lookup(t, &look) == n);
			ASSERT(tree_min(t) <= (void *)n);
			ASSERT(tree_max(t) >= (void *)n);
			n->n_active = 0;
			tree_delete(t, n);
			ASSERT(tree_valid(t));
			ASSERT(tree_lookup(t, &look) == NULL);
		} else {
			ASSERT(tree_try_delete(t, &look) == NULL);
			ASSERT(tree_valid(t));
			ASSERT(tree_try_delete(t, n) == NULL);
			ASSERT(tree_valid(t));
			ASSERT(tree_lookup(t, &look) == NULL);
			n->n_active = 1;
			tree_insert(t, n);
			ASSERT(tree_valid(t));
			ASSERT(tree_lookup(t, &look) == n);
		}

		if (rand32() % 10 == 0 && !tree_empty(t)) {
			min = tree_min(t);
			min->n_value += max_nodes;
			ASSERT(!tree_valid(t) || tree_nodes(t) == 1);
			min->n_value -= max_nodes;
			ASSERT(tree_valid(t));
			n = tree_delete_min(t);
			ASSERT(tree_valid(t));
			ASSERT(n == min);
			n->n_active = 0;
		}

		if (rand32() % 10 == 0 && !tree_empty(t)) {
			max = tree_max(t);
			max->n_value -= max_nodes;
			ASSERT(!tree_valid(t) || tree_nodes(t) == 1);
			max->n_value += max_nodes;
			ASSERT(tree_valid(t));
			n = tree_delete_max(t);
			ASSERT(tree_valid(t));
			ASSERT(n == max);
			n->n_active = 0;
		}

		if (rand32() % 10 == 0) {
			n = &na[-1];
			ASSERT(tree_try_delete(t, n) == NULL);
			ASSERT(tree_valid(t));
			tree_insert(t, n);
			ASSERT(tree_valid(t));
			ASSERT(tree_min(t) == n);
			tree_delete(t, n);
			ASSERT(tree_valid(t));
			ASSERT(tree_lookup(t, n) == NULL);
		}

		if (rand32() % 10 == 0) {
			n = &na[max_nodes];
			ASSERT(tree_try_delete(t, n) == NULL);
			ASSERT(tree_valid(t));
			tree_insert(t, n);
			ASSERT(tree_valid(t));
			ASSERT(tree_max(t) == n);
			tree_delete(t, n);
			ASSERT(tree_valid(t));
			ASSERT(tree_lookup(t, n) == NULL);
		}

		ASSERT(tree_nodes(t) <= max_nodes);
	}

	walk.n_value = -1;
	walk.n_active = 0;

	tree_walk(t, tree_test_walk, &walk);

	ASSERT(tree_nodes(t) == (size_t)walk.n_active);

	if (rand32() % 4 == 0) {
		tree_teardown(t, tt_node_destroy, &walk);
		goto out;
	}

	while (!tree_empty(t)) {
		if (rand32() % 3 == 0)
			n = tree_try_delete(t, tree_root(t));
		else if (rand32() % 2 == 0)
			n = tree_delete_min(t);
		else
			n = tree_delete_max(t);
		ASSERT(tree_valid(t));
		ASSERT(n->n_active);
		n->n_active = 0;
		walk.n_active--;
	}
out:
	ASSERT(walk.n_active == 0);
	tree_fini(t);
}

void
tree_test(void)
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 12; j++)
			tree_test_one(1L << j, 4LL << j);
}

int
main(int argc, char *argv[])
{
	tree_test();
	return (0);
}
