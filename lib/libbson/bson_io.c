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

#include <bson.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>

static int
bson_read_resize(bson_t *b, json_scope_t js, char **jpp, size_t *sizep)
{
	size_t osize, nsize;
	char *o, *n;

	osize = *sizep;
	o = *jpp;

	if (js == JSON_BSON) {
		/*
		 * When reading BSON from an fd or stream (FILE *), the first
		 * read is 4 bytes to get the size; the second read uses the
		 * data from the first read (contained in 'o') to determine
		 * said size, and then reads exactly that many bytes.
		 * It is important not to read beyond the end of document,
		 * so that a stream of BSON packets can be correctly read
		 * by calling bson_read_{fd,stream}() in a loop without
		 * assuming the fd/stream is capable of seeking backward.
		 */
		nsize = osize ? (size_t)bson_get_size(o) : sizeof (int32_t);
	} else {
		/*
		 * For JSON documents, the size is not known until the data
		 * is parsed, so we just double the buffer size and keep
		 * reading until EOF.  If we ever decide that we care about
		 * reading streams of JSON packets, we'll need to change this
		 * logic to read one byte at a time until the closing '}'.
		 */
		nsize = osize ? 2 * osize : 1;
	}

	if (nsize <= osize)
		return (EINVAL);

	n = vmem_alloc(b->b_vmem, nsize, VM_NOSLEEP);
	/* This can happen if nsize is way too large (i.e. bad BSON size) */
	if (n == NULL)
		return (EINVAL);

	memmove(n, o, osize);
	vmem_free(b->b_vmem, o, osize);

	*jpp = n;
	*sizep = nsize;

	return (0);
}

int
bson_read_buf(bson_t *b, off_t d, const char *p, json_scope_t js, const char *j,
    json_parse_cb *cb, void *arg)
{
	return (bson_from_json(b, d, p, js, j, cb, arg));
}

static int
bson_read_fd_or_stream(bson_t *b, off_t d, const char *p, json_scope_t js,
    int fd, FILE *fp, json_parse_cb *cb, void *arg)
{
	size_t offset = 0;
	size_t size = 0;
	char *j = NULL;
	ssize_t rsize;
	int err = 0;

	if (b->b_vmem == NULL)
		return (ENOMEM);

	do {
		if ((err = bson_read_resize(b, js, &j, &size)) != 0)
			break;

		if (fp != NULL) {
			while ((rsize =
			    fread(j + offset, 1, size - offset, fp)) != 0)
				offset += rsize;
			err = ferror(fp);
		} else {
			while ((rsize =
			    read(fd, j + offset, size - offset)) > 0)
				offset += rsize;
			err = rsize < 0 ? errno : 0;
		}

		if (js == JSON_BSON && size > sizeof (int32_t))
			break;

	} while (offset >= size && err == 0);

	if (offset < size)
		j[offset] = '\0';

	if (err == 0)
		err = (offset == 0) ? ENOENT : bson_from_json(b, d, p, js, j,
                    cb, arg);

	vmem_free(b->b_vmem, j, size);

	return (err);
}

int
bson_read_fd(bson_t *b, off_t d, const char *p, json_scope_t js, int fd,
    json_parse_cb *cb, void *arg)
{
	return (bson_read_fd_or_stream(b, d, p, js, fd, NULL, cb, arg));
}

int
bson_read_stream(bson_t *b, off_t d, const char *p, json_scope_t js, FILE *fp,
    json_parse_cb *cb, void *arg)
{
	return (bson_read_fd_or_stream(b, d, p, js, -1, fp, cb, arg));
}

int
bson_read_file(bson_t *b, off_t d, const char *p, json_scope_t js,
    const char *path, json_parse_cb *cb, void *arg)
{
	int fd, err;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (errno);

	err = bson_read_fd(b, d, p, js, fd, cb, arg);
	(void) close(fd);

	return (err);
}

int
bson_write_alloc(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, char **jpp, size_t *jsize)
{
	void *j = NULL;
	size_t size = 0;
	int err = 0;

	if (b->b_vmem == NULL)
		return (ENOMEM);

	err = bson_to_json(b, d, p, js, jf, j, size, &size);
	if (err)
		return (err);

	j = vmem_alloc(b->b_vmem, size, VM_SLEEP);

	err = bson_to_json(b, d, p, js, jf, j, size, &size);
	if (err) {
		vmem_free(b->b_vmem, j, size);
		return (err);
	}

	*jpp = j;
	*jsize = size;

	return (0);
}

void
bson_write_free(bson_t *b, char *j, size_t size)
{
	vmem_free(b->b_vmem, j, size);
}

int
bson_write_buf(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, char *j, size_t bufsize, size_t *jsize)
{
	return (bson_to_json(b, d, p, js, jf, j, bufsize, jsize));
}

int
bson_write_fd(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, int fd)
{
	char *j;
	size_t size, iosize;
	int err;

	err = bson_write_alloc(b, d, p, js, jf, &j, &size);
	iosize = size - (js != JSON_BSON);		// elide \0 if ASCII
	if (err == 0) {
		ssize_t wsize = write(fd, j, iosize);
		if (wsize != (ssize_t)iosize)
			err = wsize < 0 ? errno : EIO;
		bson_write_free(b, j, size);
	}

	return (err);
}

int
bson_write_stream(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, FILE *fp)
{
	char *j;
	size_t size, iosize;
	int err;

	err = bson_write_alloc(b, d, p, js, jf, &j, &size);
	iosize = size - (js != JSON_BSON);		// elide \0 if ASCII
	if (err == 0) {
		size_t wsize = fwrite(j, 1, iosize, fp);
		if (wsize != iosize)
			err = ferror(fp);
		bson_write_free(b, j, size);
	}

	return (err);
}

int
bson_write_file(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, const char *path)
{
	int fd, err;

	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
	if (fd < 0)
		return (errno);

	err = bson_write_fd(b, d, p, js, jf, fd);
	(void) close(fd);

	return (err);
}
