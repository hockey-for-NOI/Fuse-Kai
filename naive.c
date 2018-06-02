/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This file system mirrors the existing file system hierarchy of the
 * system, starting at the root file system. This is implemented by
 * just "passing through" all requests to the corresponding user-space
 * libc functions. Its performance is terrible.
 *
 * Compile with
 *
 *     gcc -Wall passthrough.c `pkg-config fuse3 --cflags --libs` -o passthrough
 *
 * ## Source code ##
 * \include passthrough.c
 */


#define FUSE_USE_VERSION 31

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdlib.h>
#include <time.h>

#include <pthread.h>
#include <json.h>

typedef	long long	ll;

const	int	P = 0x78000001;
const	int	R = 31;

inline	int	powr2(int x, int base)
{
	ll s = (x & 1 ? base : 1), t = base;
	while (x >>= 1)
	{
		t = (t * t) % P;
		if (x & 1) s = (s * t) % P;
	}
	return s;
}
inline  int powr(int x) {return powr2(x, R);}

const   char    server_addr_str[] = "120.25.160.91";
const   char    my_fuse_path[] = "/.myfuse/";
const	unsigned	short	port0 = 12345;
const	int	TIMEOUT_SEC = 5;

inline  void myseed(void) {srand48(time(0));}
inline  int myrand(void) {return lrand48();}

struct MyGlobalConnStorage
{
    struct sockaddr_in serv_addr;
    int connfd;
    pthread_mutex_t lock;
    char *sndbuf, *rcvbuf;
}   global_conn_storage;


static int myread(int q0, int q1, char* buf, int size, int offset)
{
    json_object *obj, *idx;
    obj = json_object_new_object();
    idx = json_object_new_object();
    json_object_object_add(obj, "op", json_object_new_int(2));
    json_object_object_add(idx, "q0", json_object_new_int(q0));
    json_object_object_add(idx, "q1", json_object_new_int(q1));

    while (size)
    {
        int blkno = offset >> 12;
        json_object_object_add(idx, "blkno", json_object_new_int(blkno));
        json_object_object_add(obj, "key", json_object_to_json_string(idx));

        pthread_mutex_lock(&global_conn_storage.lock);

        sprintf(sndbuf, "POST / HTTP/1.1\r\n%s", json_object_get_string(obj));
        //TODO 

        pthread_mutex_unlock(&global_conn_storage.lock);

        json_object_object_del(idx, "blkno");
        json_object_object_del(obj, "key");
    }

    json_object_put(obj);
    json_object_put(idx);
}

static int mywrite(int q0, int q1, char const* buf, int size, int offset)
{
}

static char* packpath(const char* path)
{
    int l1 = strlen(getenv("HOME")), l2 = strlen(my_fuse_path), l3 = strlen(path);
    char *buf = malloc(l1 + l2 + l3 + 1);
    memcpy(buf, getenv("HOME"), l1);
    memcpy(buf + l1, my_fuse_path, l2);
    memcpy(buf + l1 + l2, path, l3);
    buf[l1 + l2 + l3] = 0;
    return buf;
}


static void *xmp_init(struct fuse_conn_info *conn,
		      struct fuse_config *cfg)
{
	(void) conn;
	cfg->use_ino = 1;

	/* Pick up changes from lower filesystem right away. This is
	   also necessary for better hardlink support. When the kernel
	   calls the unlink() handler, it does not know the inode of
	   the to-be-removed entry and can therefore not invalidate
	   the cache of the associated inode - resulting in an
	   incorrect st_nlink value being reported for any remaining
	   hardlinks to this inode. */
	cfg->entry_timeout = 0;
	cfg->attr_timeout = 0;
	cfg->negative_timeout = 0;

	return NULL;
}

static void *pack_init(struct fuse_conn_info *conn,
		      struct fuse_config *cfg)
{
	mkdir(packpath(""), 0755);

    myseed();

	struct sockaddr_in serv_addr0;

	inet_pton(AF_INET, server_addr_str, &serv_addr0.sin_addr);

	serv_addr0.sin_family = AF_INET;
	serv_addr0.sin_port = htons(port0);

    int connfd0 = socket(AF_INET, SOCK_STREAM, 0);

	struct timeval tv;
	tv.tv_sec = TIMEOUT_SEC;
	tv.tv_usec = 0;
	setsockopt(connfd0, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
	setsockopt(connfd0, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    global_conn_storage.serv_addr = serv_addr0;
    global_conn_storage.connfd = connfd0;
    glboal_conn_storage.sndbuf = malloc(5000);
    glboal_conn_storage.rcvbuf = malloc(5000);

    return xmp_init(conn, cfg);
}

static int modified_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

    if (S_ISREG(stbuf->st_mode))
    {
        res = open(path, O_RDWR | O_CREAT, 0755);
        if (res == -1)
            return -errno;

        int data[3];
        if (pread(res, (void*)data, 12, 0) != 12)
            return -errno;

        stbuf->st_size = data[2];
    }

	return 0;
}

static int pack_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *fi)
{
    char* ppath = packpath(path);
    int ret = modified_getattr(ppath, stbuf, fi);
    free(ppath);
    return ret;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi,
		       enum fuse_readdir_flags flags)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	(void) flags;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int pack_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi,
		       enum fuse_readdir_flags flags)
{
    char* ppath = packpath(path);
    int ret = xmp_readdir(ppath, buf, filler, offset, fi, flags);
    free(ppath);
    return ret;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int pack_mkdir(const char *path, mode_t mode)
{
    char* ppath = packpath(path);
    int ret = xmp_mkdir(ppath, mode);
    free(ppath);
    return ret;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int pack_rmdir(const char *path)
{
    char* ppath = packpath(path);
    int ret = xmp_rmdir(ppath);
    free(ppath);
    return ret;
}

static int xmp_rename(const char *from, const char *to, unsigned int flags)
{
	int res;

	if (flags)
		return -EINVAL;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int pack_rename(const char *from, const char *to, unsigned int flags)
{
    char *pfrom = packpath(from), *pto = packpath(to);
    int ret = xmp_rename(pfrom, pto, flags);
    free(pfrom); free(pto);
    return ret;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int pack_unlink(const char *path)
{
    char* ppath = packpath(path);
    int ret = xmp_unlink(ppath);
    free(ppath);
    return ret;
}

static int modified_create(const char *path, mode_t mode,
		      struct fuse_file_info *fi)
{
	int res;

	res = open(path, O_RDWR | O_CREAT | O_TRUNC, mode);
	if (res == -1)
		return -errno;

    int data[3]; data[0] = myrand(); data[1] = myrand(); data[2] = 0;
    if (pwrite(res, (void*)data, 12, 0) == -1)
        return -errno;

    if (!fi)
	    close(res);
    else
        fi->fh = res;
	return 0;
}

static int pack_create(const char *path, mode_t mode,
		      struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = modified_create(ppath, mode, fi);
    free(ppath);
    return ret;
}

static int modified_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	res = open(path, O_RDWR | O_CREAT, 0755);
	if (res == -1)
		return -errno;

    int data[3];
    if (pread(res, (void*)data, 12, 0) != 12)
    {
        close(res);
        res = open(path, O_RDWR | O_TRUNC, 0755);
	    if (res == -1)
		    return -errno;

        data[0] = myrand(); data[1] = myrand(); data[2] = 0;
        if (pwrite(res, (void*)data, 12, 0) != 12)
        {
            return -errno;
        }
    }

    if (fi->flags & O_TRUNC)
    {
        data[2] = 0;
        if (pwrite(res, (void*)data, 12, 0) != 12)
        {
            return -errno;
        }
    }

    if (fi)
        fi->fh = res;
    else
        close(res);

	return 0;
}

static int pack_open(const char *path, struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = modified_open(ppath, fi);
    free(ppath);
    return ret;
}

static int modified_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;

    if (!fi)
	    fd = open(path, O_RDWR);
    else
        fd = fi->fh;
	
	if (fd == -1)
		return -errno;

    int data[3];
    if (pread(fd, (void*)data, 12, 0) == -1)
        return -errno;

    if (offset > data[2])
        return 0;

    if (offset + size > data[2])
        size = data[2] - offset;

	res = myread(data[0], data[1], buf, size, offset);

    if (!fi)
    	close(fd);

    if (size + offset > data[2])
        return data[2] - size;

	return res;
}

static int pack_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = modified_read(ppath, buf, size, offset, fi);
    free(ppath);
    return ret;
}

static int modified_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
    if (!fi)
	    fd = open(path, O_RDWR);
    else
        fd = fi->fh;
	
	if (fd == -1)
		return -errno;

    int data[3];
    if (pread(fd, (void*)data, 12, 0) == -1)
        return -errno;

    if (size + offset > data[2])
    {
        data[2] = size + offset;
        if (pwrite(fd, (void*)data, 12, 0) == -1)
            return -errno;
    }

	res = mywrite(data[0], data[1], buf, size, offset);

    if (!fi)
	    close(fd);

	return res;
}

static int pack_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = modified_write(ppath, buf, size, offset, fi);
    free(ppath);
    return ret;
}

static int modified_truncate(const char *path, off_t offset,
             struct fuse_file_info *fi)
{
	int fd;

	(void) fi;
    if (!fi)
	    fd = open(path, O_RDWR);
    else
        fd = fi->fh;
	
	if (fd == -1)
		return -errno;

    int data[3];
    if (pread(fd, (void*)data, 12, 0) == -1)
        return -errno;

    if (offset != data[2])
    {
        data[2] = offset;
        if (pwrite(fd, (void*)data, 12, 0) == -1)
            return -errno;
    }

    if (!fi)
	    close(fd);

	return 0;
}

static int pack_truncate(const char *path, off_t offset,
             struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = modified_truncate(ppath, offset, fi);
    free(ppath);
    return ret;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	close(fi->fh);
	return 0;
}

static int pack_release(const char *path, struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = xmp_release(ppath, fi);
    free(ppath);
    return ret;
}

static struct fuse_operations xmp_oper = {
	.init       = pack_init,
	.getattr	= pack_getattr,
	.readdir	= pack_readdir,
	.mkdir		= pack_mkdir,
	.rmdir		= pack_rmdir,
	.rename		= pack_rename,
    .unlink     = pack_unlink,
	.open		= pack_open,
	.create 	= pack_create,
	.read		= pack_read,
	.write		= pack_write,
    .truncate   = pack_truncate,
    .release    = pack_release
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &xmp_oper, NULL);
}
