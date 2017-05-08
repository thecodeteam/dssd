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
 * ustat utility
 *
 * This program provides a flexible way to display ustats and sample them over
 * time.  It can used to examine processes, archived files, and cores, and has
 * fancy formatting for the known classes implemented by libustat.
 *
 * Input selection options:
 * -f - examine specified stat file or core file
 * -p - examine specified pid
 *
 * Stat selection options:
 * -c - match class and enable class-specific fancy formatting
 * -g - match group name ("g") or group path glob pattern ("a.*.g")
 * -n - match stat name ("s") or stat path glob pattern ("a.*.s")
 * -T - match stats of specified types ("int8" or "string" etc)
 *
 * Output formatting options:
 * -h - print header line before each file or process's statistics
 * -l - print names only but no values
 * -r - print integer stats using given radix (0=default, 8=oct, 10=dec, 16=hex)
 * -s - print snapshot time for each stat
 * -t - print type for each stat
 * -v - print values only and not names
 *
 * Loop arguments:
 * intvl - sampling interval in seconds (default = 1)
 * count - iteration count (-p default = unlimited, -f default = 1)
 */

#include <inttypes.h>
#include <fnmatch.h>
#include <alloca.h>
#include <poll.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>

#include <bson.h>
#include <ustat.h>
#include <ustat_io.h>
#include <ustat_hg.h>
#include <ustat_ms.h>

#define	USTAT_SUCCESS	0
#define	USTAT_ERROR	1
#define	USTAT_USAGE	2

struct ustat_opts {
	ustat_handle_t **o_statv;
	int o_statc;
	char **o_cmdv;
	char **o_gpatv;
	int o_gpatc;
	char **o_npatv;
	int o_npatc;
	int o_radix;
	int o_flags;
	uint32_t o_types;
	const char *o_class;
	char *o_nname;
	size_t o_nnamelen;
	uint64_t o_iter;
	bson_t o_bson;
	off_t o_bson_root;
};

#define	OPT_NAME_TYPE	0x01
#define	OPT_NAME_ONLY	0x02
#define	OPT_DATA_ONLY	0x04
#define	OPT_SHOW_COMM	0x08
#define	OPT_SHOW_TIME	0x10
#define	OPT_HDRL_DONE	0x20
#define	OPT_SHOW_JSON	0x40

static void __attribute__ ((format(printf, 1, 2)))
oprintf(const char *format, ...)
{
	va_list ap;
	int rv;

	va_start(ap, format);
	rv = vprintf(format, ap);
	va_end(ap);

	if (rv < 0)
		err(USTAT_ERROR, "failed to write output");
}

static int
walk_misc(ustat_handle_t *h, ustat_struct_t *s0, void *uarg)
{
	const char *gname = ustat_getgname(s0);
	const char *cname = ustat_getcname(s0);

	struct ustat_opts *op = uarg;
	ustat_named_t *n = NULL;

	ustat_struct_t *s;
	ssize_t glen;
	int i, m;

	if (op->o_class != NULL && strcmp(cname, op->o_class) != 0)
		return (0); /* class did not match */

	for (m = 0, i = 0; i < op->o_gpatc; i++)
		m |= !fnmatch(op->o_gpatv[i], gname, 0);

	if (op->o_gpatc != 0 && m == 0)
		return (0); /* group did not match */

	if ((s = ustat_snapshot(s0)) == NULL) {
		warn("ustat_snapshot(%s) failed", gname);
		s = s0; /* just use previous snap */
	}

	glen = snprintf(op->o_nname, op->o_nnamelen, "%s.", gname);

	/* use the group-level JSON parser if no name-level key was specified */
	if ((op->o_flags & OPT_SHOW_JSON) && op->o_types == 0 &&
	    op->o_npatc == 0)
		return (ustat_exportv_bson(s, ustat_getnnames(s), &op->o_bson,
		    op->o_bson_root));

	while ((n = ustat_getnext(s, n)) != NULL) {
		if (op->o_types != 0 && !(op->o_types & (1 << n->usn_type)))
			continue; /* type did not match */

		(void) strncpy(&op->o_nname[glen], n->usn_name,
		    op->o_nnamelen - glen - 1);

		for (m = 0, i = 0; i < op->o_npatc; i++) {
			if (strchr(op->o_npatv[i], '.') != NULL)
				m |= !fnmatch(op->o_npatv[i], op->o_nname, 0);
			else
				m |= !fnmatch(op->o_npatv[i], n->usn_name, 0);
		}

		if (op->o_npatc != 0 && m == 0)
			continue; /* name did not match */

		if (op->o_flags & OPT_SHOW_JSON) {
			if (ustat_export_bson(s, n, &op->o_bson,
			    op->o_bson_root) != 0)
				err(USTAT_ERROR, "failed to export bson");
			continue;
		}

		if (op->o_flags & OPT_SHOW_TIME)
			oprintf("%" PRIx64 ":", ustat_getatime(s));

		if (op->o_flags & OPT_NAME_ONLY) {
			if (op->o_flags & OPT_NAME_TYPE)
				oprintf("%s:%s", op->o_nname,
				    ustat_type2str(n->usn_type));
			else
				oprintf("%s", op->o_nname);
		} else if (!(op->o_flags & OPT_DATA_ONLY)) {
			if (op->o_statc > 1)
				oprintf("%s[%d]:",
				    ustat_comm(h), ustat_pid(h));
			if (op->o_flags & OPT_NAME_TYPE)
				oprintf("%s:%s=", op->o_nname,
				    ustat_type2str(n->usn_type));
			else
				oprintf("%s=", op->o_nname);
		}

		if (!(op->o_flags & OPT_NAME_ONLY) &&
		    ustat_printf(h, op->o_radix, n) < 0)
			err(USTAT_ERROR, "failed to write output");

		oprintf("\n");
	}

	return (0);
}

static int
walk_io(ustat_handle_t *h, ustat_struct_t *s0, void *uarg)
{
	struct ustat_opts *op = uarg;

	const char *gname = ustat_getgname(s0);
	const char *cname = ustat_getcname(s0);
	int statc = sizeof (ustat_io_t) / sizeof (ustat_named_t);

	ustat_io_delta_t d;
	ustat_io_t *uio;
	int i, m;

	if (strcmp(cname, op->o_class) != 0)
		return (0); /* class did not match */

	for (m = 0, i = 0; i < op->o_gpatc; i++)
		m |= !fnmatch(op->o_gpatv[i], gname, 0);

	if (op->o_gpatc != 0 && m == 0)
		return (0); /* group did not match */

	if ((uio = ustat_snapshot(s0)) == NULL) {
		warn("ustat_snapshot(%s) failed", gname);
		return (0); /* skip to next group */
	}

	if (op->o_flags & OPT_SHOW_JSON) {
		if (ustat_exportv_bson(uio, statc, &op->o_bson, op->o_bson_root)
		    != 0)
			err(USTAT_ERROR, "failed to export io");
		return (0);
	}

	if (op->o_iter == 1 && !(op->o_flags & OPT_HDRL_DONE)) {
		oprintf("%7s%7s%7s%9s%9s%8s%8s%8s %s\n",
		    "IOPS", "RIOPS", "WIOPS", "R-BW", "W-BW",
		    "AVG_WAT", "AVG_RUN", "AVG_LAT", "NAME");
		op->o_flags |= OPT_HDRL_DONE;
	}

	ustat_io_delta(uio, &d);

	(void) ustat_fprintf_unit(stdout, 7, d.uiod_t_iops, &ustat_unit_iops);
	(void) ustat_fprintf_unit(stdout, 7, d.uiod_r_iops, &ustat_unit_iops);
	(void) ustat_fprintf_unit(stdout, 7, d.uiod_w_iops, &ustat_unit_iops);

	(void) ustat_fprintf_unit(stdout, 9, d.uiod_r_bw, &ustat_unit_tput);
	(void) ustat_fprintf_unit(stdout, 9, d.uiod_w_bw, &ustat_unit_tput);

	if (ferror(stdout))
		err(USTAT_ERROR, "failed to write output");

	oprintf("%5.1fus %5.1fus %5.1fus %s\n",
	    d.uiod_avgw_us, d.uiod_avgr_us, d.uiod_avgt_us, gname);

	return (0);
}

static int
walk_hg(ustat_handle_t *h, ustat_struct_t *s0, void *uarg)
{
	struct ustat_opts *op = uarg;

	const char *gname = ustat_getgname(s0);
	const char *cname = ustat_getcname(s0);
	int statc = sizeof (ustat_hg_t) / sizeof (ustat_named_t);

	ustat_hg_t *hg;
	int i, m;

	if (strcmp(cname, op->o_class) != 0)
		return (0); /* class did not match */

	for (m = 0, i = 0; i < op->o_gpatc; i++)
		m |= !fnmatch(op->o_gpatv[i], gname, 0);

	if (op->o_gpatc != 0 && m == 0)
		return (0); /* group did not match */

	if ((hg = ustat_snapshot(s0)) == NULL) {
		warn("ustat_snapshot(%s) failed", gname);
		return (0); /* skip to next group */
	}

	if (op->o_flags & OPT_SHOW_JSON) {
		if (ustat_exportv_bson(hg, statc, &op->o_bson, op->o_bson_root)
		    != 0)
			err(USTAT_ERROR, "failed to export hg");
		return (0);
	}

	switch (hg->ushg_vtype.usn_type) {
	case USTAT_TYPE_DELTA:
		ustat_hg_fprint_cyctotime(stdout, gname, hg,
		    ustat_get_u32(hg, &hg->ushg_ctons));
		break;
	case USTAT_TYPE_SIZE:
		ustat_hg_fprint_unit(stdout, gname, hg, &ustat_unit_size);
		break;
	case USTAT_TYPE_UINT64:
		ustat_hg_fprint_unit(stdout, gname, hg, NULL);
		break;
	default:
		return (-1);
	}

	return (0);
}

static int
walk_ms(ustat_handle_t *h, ustat_struct_t *s0, void *uarg)
{
	struct ustat_opts *op = uarg;
	ustat_ms_t *ms;
	int i, m;

	const char *gname = ustat_getgname(s0);
	const char *cname = ustat_getcname(s0);
	int statc = sizeof (ustat_ms_t) / sizeof (ustat_named_t);

	if (strcmp(cname, op->o_class) != 0)
		return (0); /* class did not match */

	for (m = 0, i = 0; i < op->o_gpatc; i++)
		m |= !fnmatch(op->o_gpatv[i], gname, 0);

	if (op->o_gpatc != 0 && m == 0)
		return (0); /* group did not match */

	if ((ms = ustat_snapshot(s0)) == NULL) {
		warn("ustat_snapshot(%s) failed", gname);
		return (0); /* skip to next group */
	}

	if (op->o_flags & OPT_SHOW_JSON) {
		if (ustat_exportv_bson(ms, statc, &op->o_bson, op->o_bson_root)
		    != 0)
			err(USTAT_ERROR, "failed to export ms");
		return (0);
	}

	oprintf("%s\n", gname);
	ustat_ms_print(ms, stdout);
	return (0);
}

static int
getopt_int(const char *opt, const char *s, int64_t min, int64_t max)
{
	int64_t v;
	char *q;

	errno = 0;
	v = strtoll(s, &q, 0);

	if (errno != 0)
		err(USTAT_USAGE, "invalid integer for %s: %s", opt, s);

	if (q == s || *q != '\0')
		errx(USTAT_USAGE, "invalid integer for %s: %s", opt, s);

	if (v < min || v > max) {
		errx(USTAT_USAGE, "invalid integer for %s: value %s is out of "
		    "range [%" PRId64 "..%" PRId64 "]", opt, s, min, max);
	}

	return ((int)v);
}

static int
usage(FILE *fp, const char *arg0)
{
	(void) fprintf(fp, "Usage: %s "
	    "[-hjlstv] [-c class] [-f file] [-g name] [-n name]\n"
	    "\t[-p pid] [-r radix] [-T type] [intvl [count]]\n", arg0);

	(void) fprintf(fp, "\t-c display stats with matching class\n");
	(void) fprintf(fp, "\t-f display stats from the specified file\n");
	(void) fprintf(fp, "\t-g display stats with matching group name\n");
	(void) fprintf(fp, "\t-h display header line for each file/proc\n");
	(void) fprintf(fp, "\t-j display stats as JSON\n");
	(void) fprintf(fp, "\t-l display names only and not values\n");
	(void) fprintf(fp, "\t-n display stats with matching stat name\n");
	(void) fprintf(fp, "\t-p display stats for the specified process\n");
	(void) fprintf(fp, "\t-r display raw integers in specified radix\n");
	(void) fprintf(fp, "\t-s display snapshot time for each stat\n");
	(void) fprintf(fp, "\t-t display names and types\n");
	(void) fprintf(fp, "\t-T display stats with matching type\n");
	(void) fprintf(fp, "\t-v display values only and not names\n");
	(void) fprintf(fp, "\tEnvironment:\n");
	(void) fprintf(fp, "\tUSTAT_DEBUG=VERBOSE - send debug to stderr\n");

	return (USTAT_USAGE);
}

static int
init_bson(struct ustat_opts *o, const char *cmd)
{
	bson_t *b = &o->o_bson;

	bson_init(b, NULL, 0, vmem_heap, '.', BSON_NULL, bson_fatal);

	if (bson_set(b, 0, NULL, &o->o_bson_root, BSON_OBJECT, bson_empty) != 0)
		return (-1);

	if ((o->o_flags & OPT_SHOW_COMM) && bson_add_object(b, o->o_bson_root,
	    cmd, &o->o_bson_root, bson_empty) != 0)
		return (-1);

	return (0);
}

static void
print_json(struct ustat_opts *o)
{
	bson_t *b = &o->o_bson;
	off_t root = 0;  /* print the entire document */
	char *jstr = NULL;
	size_t l = 0, used = 0;

	if (bson_to_json(b, root, NULL, JSON_PURE, JSON_PRETTY, NULL, 0,
	    &l) != 0)
		err(USTAT_ERROR, "bson_to_json len failed");

	if (l == 0)
		return;

	jstr = vmem_alloc(vmem_heap, l, VM_SLEEP);

        if (bson_to_json(b, root, NULL, JSON_PURE, JSON_PRETTY, jstr, l,
            &used) != 0)
		err(USTAT_ERROR, "bson_to_json failed");

	if (used > 0)
		oprintf("%s", jstr);

	vmem_free(vmem_heap, jstr, l);
}

int
main(int argc, char *argv[])
{
	int oflags = USTAT_RETAIN_DELTA | O_RDONLY;
	ustat_walk_f *iter_w = walk_misc;
	int iter_i = 1;
	int iter_c = -1;

	struct ustat_opts opts;
	ustat_handle_t *h;
	ustat_type_t t;
	pid_t p = -1;
	int c;

	bzero(&opts, sizeof (opts));

	opts.o_statv = alloca(argc * sizeof (ustat_handle_t *));
	opts.o_cmdv = alloca(argc * sizeof (char *));
	opts.o_gpatv = alloca(argc * sizeof (const char *));
	opts.o_npatv = alloca(argc * sizeof (const char *));

	while ((c = getopt(argc, argv, "+c:f:g:hjln:p:r:stT:v")) != EOF) {
		switch (c) {
		case 'c':
			opts.o_class = optarg;
			if (strcmp(optarg, "io") == 0)
				iter_w = walk_io;
			else if (strcmp(optarg, "hg") == 0)
				iter_w = walk_hg;
			else if (strcmp(optarg, "ms") == 0)
				iter_w = walk_ms;
			else
				iter_w = walk_misc;
			break;
		case 'f':
			opts.o_statv[opts.o_statc++] = h =
			    ustat_open_file(USTAT_VERSION, optarg, oflags);
			if (h == NULL)
				err(USTAT_ERROR, "failed to open %s", optarg);
			break;
		case 'g':
			opts.o_gpatv[opts.o_gpatc++] = optarg;
			break;
		case 'h':
			opts.o_flags |= OPT_SHOW_COMM;
			break;
		case 'j':
			opts.o_flags |= OPT_SHOW_JSON;
			break;
		case 'l':
			opts.o_flags |= OPT_NAME_ONLY;
			opts.o_flags &= ~OPT_DATA_ONLY;
			break;
		case 'n':
			opts.o_npatv[opts.o_npatc++] = optarg;
			break;
		case 'p':
			p = getopt_int("-p", optarg, 1, INT32_MAX);
			opts.o_statv[opts.o_statc++] = h =
			    ustat_open_proc(USTAT_VERSION, p, oflags);
			if (h == NULL)
				err(USTAT_ERROR, "failed to open %s", optarg);
			break;
		case 'r':
			opts.o_radix = getopt_int("-r", optarg, 0, 16);
			break;
		case 's':
			opts.o_flags |= OPT_SHOW_TIME;
			break;
		case 't':
			opts.o_flags |= OPT_NAME_TYPE;
			opts.o_flags &= ~OPT_DATA_ONLY;
			break;
		case 'T':
			if ((t = ustat_str2type(optarg)) == (ustat_type_t)-1)
				errx(USTAT_USAGE, "invalid type -- %s", optarg);
			opts.o_types |= 1u << t;
			break;
		case 'v':
			opts.o_flags |= OPT_DATA_ONLY;
			opts.o_flags &= ~OPT_NAME_ONLY;
			break;
		default:
			return (usage(stderr, argv[0]));
		}
	}

	if (optind < argc)
		iter_i = getopt_int("intvl", argv[optind++], 0, INT32_MAX);

	if (optind < argc)
		iter_c = getopt_int("count", argv[optind++], 0, INT32_MAX);

	if (optind < argc)
		errx(USTAT_USAGE, "unexpected argument -- %s", argv[optind]);

	if (opts.o_statc == 0)
		errx(USTAT_USAGE, "at least one -f or -p option is required");

	if (iter_c == -1 && p == -1)
		iter_c = 1; /* reset default count to one if no -p options */

	for (c = 0; c < opts.o_statc; c++) {
		ssize_t len = ustat_conf(opts.o_statv[c], USTAT_CONF_PATH_MAX);
		const char *comm = ustat_comm(opts.o_statv[c]);
		pid_t pid = ustat_pid(opts.o_statv[c]);

		if (opts.o_nnamelen < (size_t)len)
			opts.o_nnamelen = (size_t)len;

		len = snprintf(NULL, 0, "%s[%d]", comm, pid) + 1;
		opts.o_cmdv[c] = alloca(len);
		(void) snprintf(opts.o_cmdv[c], len, "%s[%d]", comm, pid);
	}

	opts.o_nname = alloca(opts.o_nnamelen);
	bzero(opts.o_nname, opts.o_nnamelen);

	for (opts.o_iter = 1; iter_c < 0 || iter_c-- > 0; opts.o_iter++) {
		for (c = 0; c < opts.o_statc; c++) {
			if (opts.o_flags & OPT_SHOW_JSON) {
				if (init_bson(&opts, opts.o_cmdv[c]) != 0)
					err(USTAT_ERROR, "failed to init bson");
			} else if (opts.o_flags & OPT_SHOW_COMM)
				oprintf("%s:\n", opts.o_cmdv[c]);

			(void) ustat_update(opts.o_statv[c]);
			(void) ustat_walk(opts.o_statv[c], NULL, iter_w, &opts);

			if (opts.o_flags & OPT_SHOW_JSON) {
				print_json(&opts);
				bson_fini(&opts.o_bson);
			}
		}
		if (iter_c != 0 && iter_i > 0)
			(void) poll(NULL, 0, iter_i * 1000);
	}

	for (c = 0; c < opts.o_statc; c++)
		ustat_close(opts.o_statv[c]);

	return (USTAT_SUCCESS);
}
