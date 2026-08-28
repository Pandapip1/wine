/*
 * Server-side file management
 *
 * Copyright (C) 1998 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif
#include <time.h>
#include <unistd.h>
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#include <poll.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"

#include "file.h"
#include "handle.h"
#include "thread.h"
#include "request.h"
#include "process.h"
#include "security.h"

static const WCHAR file_name[] = {'F','i','l','e'};

#ifndef XATTR_USER_PREFIX
# define XATTR_USER_PREFIX "user."
#endif
#define XATTR_USER_PREFIX_LEN (sizeof(XATTR_USER_PREFIX) - 1)
#define XATTR_EA XATTR_USER_PREFIX "WINEEA"

struct xattr_stream
{
    struct list entry;
    dev_t dev;
    ino_t ino;
    int base_fd;
    char *xattr_name;
    char *temp_name;
    unsigned int refs;
    unsigned int dirty : 1;
    unsigned int deleted : 1;
};

static struct list xattr_streams = LIST_INIT( xattr_streams );

struct type_descr file_type =
{
    { file_name, sizeof(file_name) },   /* name */
    FILE_ALL_ACCESS,                    /* valid_access */
    {                                   /* mapping */
        FILE_GENERIC_READ,
        FILE_GENERIC_WRITE,
        FILE_GENERIC_EXECUTE,
        FILE_ALL_ACCESS
    },
};

struct file
{
    struct object       obj;            /* object header */
    struct fd          *fd;             /* file descriptor for this file */
    unsigned int        access;         /* file access (FILE_READ_DATA etc.) */
    mode_t              mode;           /* file stat.st_mode */
    uid_t               uid;            /* file stat.st_uid */
    struct list         kernel_object;  /* list of kernel object pointers */
    struct xattr_stream *stream;        /* xattr-backed named stream, if any */
    unsigned int        stream_delete : 1;
};

static void file_dump( struct object *obj, int verbose );
static struct fd *file_get_fd( struct object *obj );
static struct security_descriptor *file_get_sd( struct object *obj );
static int file_set_sd( struct object *obj, const struct security_descriptor *sd, unsigned int set_info );
static struct object *file_lookup_name( struct object *obj, struct unicode_str *name,
                                      unsigned int attr, struct object *root );
static struct object *file_open_file( struct object *obj, unsigned int access,
                                      unsigned int sharing, unsigned int options );
static struct list *file_get_kernel_obj_list( struct object *obj );
static void file_destroy( struct object *obj );

static enum server_fd_type file_get_fd_type( struct fd *fd );

static const struct object_ops file_ops =
{
    .size                = sizeof(struct file),
    .type                = &file_type,
    .dump                = file_dump,
    .get_fd              = file_get_fd,
    .get_sync            = default_fd_get_sync,
    .get_sd              = file_get_sd,
    .set_sd              = file_set_sd,
    .get_full_name       = default_fd_get_full_name,
    .lookup_name         = file_lookup_name,
    .open_file           = file_open_file,
    .get_kernel_obj_list = file_get_kernel_obj_list,
    .destroy             = file_destroy,
};

static const struct fd_ops file_fd_ops =
{
    .get_fd_type   = file_get_fd_type,
    .get_file_info = default_fd_get_file_info,
    .ioctl         = default_fd_ioctl,
    .queue_async   = default_fd_queue_async,
};

/* create a file from a file descriptor */
/* if the function fails the fd is closed */
struct file *create_file_for_fd( int fd, unsigned int access, unsigned int sharing )
{
    struct file *file;
    struct stat st;

    if (fstat( fd, &st ) == -1)
    {
        file_set_error();
        close( fd );
        return NULL;
    }

    if (!(file = alloc_object( &file_ops )))
    {
        close( fd );
        return NULL;
    }

    file->mode = st.st_mode;
    file->access = default_map_access( &file->obj, access );
    file->stream = NULL;
    file->stream_delete = 0;
    list_init( &file->kernel_object );
    if (!(file->fd = create_anonymous_fd( &file_fd_ops, fd, &file->obj,
                                          FILE_SYNCHRONOUS_IO_NONALERT )))
    {
        release_object( file );
        return NULL;
    }
    allow_fd_caching( file->fd );
    return file;
}

/* create a file by duplicating an fd object */
struct file *create_file_for_fd_obj( struct fd *fd, unsigned int access, unsigned int sharing )
{
    struct file *file;
    struct stat st;

    if (fstat( get_unix_fd(fd), &st ) == -1)
    {
        file_set_error();
        return NULL;
    }

    if ((file = alloc_object( &file_ops )))
    {
        file->mode = st.st_mode;
        file->access = default_map_access( &file->obj, access );
        file->stream = NULL;
        file->stream_delete = 0;
        list_init( &file->kernel_object );
        if (!(file->fd = dup_fd_object( fd, access, sharing, FILE_SYNCHRONOUS_IO_NONALERT )))
        {
            release_object( file );
            return NULL;
        }
        set_fd_user( file->fd, &file_fd_ops, &file->obj );
    }
    return file;
}

static struct object *create_file_obj( struct fd *fd, unsigned int access, mode_t mode )
{
    struct file *file = alloc_object( &file_ops );

    if (!file) return NULL;
    file->access  = access;
    file->mode    = mode;
    file->uid     = ~(uid_t)0;
    file->fd      = fd;
    file->stream  = NULL;
    file->stream_delete = 0;
    list_init( &file->kernel_object );
    grab_object( fd );
    set_fd_user( fd, &file_fd_ops, &file->obj );
    return &file->obj;
}

int is_file_executable( const char *name )
{
    int len = strlen( name );
    return len >= 4 && (!strcasecmp( name + len - 4, ".exe") || !strcasecmp( name + len - 4, ".com" ));
}

static ssize_t stream_xattr_get( int fd, const char *name, void *value, size_t size )
{
#ifdef HAVE_SYS_XATTR_H
# ifdef XATTR_ADDITIONAL_OPTIONS
    return fgetxattr( fd, name, value, size, 0, 0 );
# else
    return fgetxattr( fd, name, value, size );
# endif
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int stream_xattr_set( int fd, const char *name, const void *value, size_t size )
{
#ifdef HAVE_SYS_XATTR_H
# ifdef XATTR_ADDITIONAL_OPTIONS
    return fsetxattr( fd, name, value, size, 0, 0 );
# else
    return fsetxattr( fd, name, value, size, 0 );
# endif
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int stream_xattr_remove( int fd, const char *name )
{
#ifdef HAVE_SYS_XATTR_H
# ifdef XATTR_ADDITIONAL_OPTIONS
    return fremovexattr( fd, name, 0 );
# else
    return fremovexattr( fd, name );
# endif
#else
    errno = ENOSYS;
    return -1;
#endif
}

/* Split file:stream[:$DATA].  Other stream types are not file data and are
 * deliberately left to normal Unix path handling. */
static int split_xattr_stream_name( const char *name, char **base_ret, char **xattr_ret )
{
    const char *component = strrchr( name, '/' );
    const char *colon, *type, *end = name + strlen(name);
    size_t base_len, stream_len;
    char *base, *xattr = NULL;

    component = component ? component + 1 : name;
    if (!(colon = strchr( component, ':' ))) return 0;
    if ((type = strchr( colon + 1, ':' )))
    {
        if (strchr( type + 1, ':' ) || strcasecmp( type + 1, "$DATA" )) return 0;
    }
    else type = end;

    base_len = colon - name;
    stream_len = type - colon - 1;
    if (!(base = mem_alloc( base_len + 1 ))) return -1;
    memcpy( base, name, base_len );
    base[base_len] = 0;

    if (stream_len)
    {
        if (!(xattr = mem_alloc( XATTR_USER_PREFIX_LEN + stream_len + 1 )))
        {
            free( base );
            return -1;
        }
        memcpy( xattr, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN );
        memcpy( xattr + XATTR_USER_PREFIX_LEN, colon + 1, stream_len );
        xattr[XATTR_USER_PREFIX_LEN + stream_len] = 0;
    }
    *base_ret = base;
    *xattr_ret = xattr;
    return 1;
}

static struct xattr_stream *find_xattr_stream( const struct stat *st, const char *name )
{
    struct xattr_stream *stream;

    LIST_FOR_EACH_ENTRY( stream, &xattr_streams, struct xattr_stream, entry )
        if (stream->dev == st->st_dev && stream->ino == st->st_ino && !strcmp( stream->xattr_name, name ))
            return stream;
    return NULL;
}

static int write_all( int fd, const void *buffer, size_t size )
{
    const char *ptr = buffer;

    while (size)
    {
        ssize_t ret = write( fd, ptr, size );
        if (ret == -1 && errno == EINTR) continue;
        if (ret <= 0) return 0;
        ptr += ret;
        size -= ret;
    }
    return 1;
}

static int sync_xattr_stream( struct xattr_stream *stream )
{
    struct stat st;
    void *buffer = NULL;
    int fd, ret = -1;

    if (stream->deleted) return stream_xattr_remove( stream->base_fd, stream->xattr_name );
    if (!stream->dirty) return 0;
    if ((fd = open( stream->temp_name, O_RDONLY )) == -1) return -1;
    if (fstat( fd, &st ) == -1 || st.st_size < 0 ||
        (st.st_size && !(buffer = mem_alloc( st.st_size )))) goto done;
    if (st.st_size && pread( fd, buffer, st.st_size, 0 ) != st.st_size) goto done;
    ret = stream_xattr_set( stream->base_fd, stream->xattr_name, buffer, st.st_size );
done:
    free( buffer );
    close( fd );
    return ret;
}

static void free_xattr_stream( struct xattr_stream *stream )
{
    list_remove( &stream->entry );
    unlink( stream->temp_name );
    close( stream->base_fd );
    free( stream->xattr_name );
    free( stream->temp_name );
    free( stream );
}

static struct object *create_xattr_stream( struct fd *root, const char *name, struct unicode_str nt_name,
                                          int flags, mode_t *mode, unsigned int access,
                                          unsigned int sharing, unsigned int options, int *handled )
{
    struct xattr_stream *stream = NULL;
    struct object *obj = NULL;
    struct stat st, path_st;
    char *base = NULL, *xattr = NULL, *value = NULL, *temp_name = NULL;
    ssize_t value_size;
    int base_fd = -1, temp_fd = -1, root_fd = AT_FDCWD;
    int split, exists, truncate_stream;

    *handled = 0;
    if ((split = split_xattr_stream_name( name, &base, &xattr )) <= 0)
    {
        if (split < 0) *handled = 1;
        return NULL;
    }

    /* This xattr contains Windows EAs and is not an alternate data stream. */
    if (xattr && !strcmp( xattr, XATTR_EA ))
    {
        *handled = 1;
        set_error( STATUS_OBJECT_NAME_NOT_FOUND );
        goto done;
    }

    /* Preserve a real Unix colon-named file if one already exists. */
    if (root && (root_fd = get_unix_fd( root )) == -1) goto done;
    if (!fstatat( root_fd, name, &path_st, 0 )) goto done;
    *handled = 1;

    /* An explicit ::$DATA spelling is just another spelling of the base file. */
    if (!xattr)
    {
        struct fd *fd = open_fd( root, base, nt_name, flags, mode, access, sharing, options );
        if (fd)
        {
            if (S_ISDIR(*mode)) obj = create_dir_obj( fd, access, *mode );
            else obj = create_file_obj( fd, access, *mode );
            release_object( fd );
        }
        goto done;
    }

    if ((base_fd = openat( root_fd, base, O_RDONLY | O_NONBLOCK )) == -1)
    {
        file_set_error();
        goto done;
    }
    if (fstat( base_fd, &st ) == -1)
    {
        file_set_error();
        goto done;
    }

    stream = find_xattr_stream( &st, xattr );
    value_size = stream ? (stream->deleted ? -1 : 0) : stream_xattr_get( base_fd, xattr, NULL, 0 );
    exists = stream ? !stream->deleted : value_size >= 0;
    truncate_stream = flags & O_TRUNC;

    if ((flags & O_EXCL) && exists)
    {
        set_error( STATUS_OBJECT_NAME_COLLISION );
        goto done;
    }
    if (!(flags & O_CREAT) && !exists)
    {
        set_error( STATUS_OBJECT_NAME_NOT_FOUND );
        goto done;
    }

    if (!stream)
    {
        if (!exists)
        {
            if (stream_xattr_set( base_fd, xattr, NULL, 0 ) == -1)
            {
                file_set_error();
                goto done;
            }
            value_size = 0;
        }
        if (value_size && (!(value = mem_alloc( value_size )) ||
                           stream_xattr_get( base_fd, xattr, value, value_size ) != value_size))
        {
            if (!value) set_error( STATUS_NO_MEMORY );
            else file_set_error();
            goto done;
        }
        if (asprintf( &temp_name, "%s/xattr-stream-XXXXXX", server_dir ) == -1)
        {
            set_error( STATUS_NO_MEMORY );
            goto done;
        }
        if ((temp_fd = mkstemp( temp_name )) == -1 || !write_all( temp_fd, value, value_size ))
        {
            file_set_error();
            goto done;
        }
        close( temp_fd );
        temp_fd = -1;

        if (!(stream = mem_alloc( sizeof(*stream) ))) goto done;
        stream->dev = st.st_dev;
        stream->ino = st.st_ino;
        stream->base_fd = base_fd;
        stream->xattr_name = xattr;
        stream->temp_name = temp_name;
        stream->refs = 0;
        stream->dirty = !exists;
        stream->deleted = 0;
        list_add_tail( &xattr_streams, &stream->entry );
        base_fd = -1;
        xattr = temp_name = NULL;
    }

    if (truncate_stream)
    {
        if (truncate( stream->temp_name, 0 ) == -1 ||
            stream_xattr_set( stream->base_fd, stream->xattr_name, NULL, 0 ) == -1)
        {
            file_set_error();
            goto done;
        }
        stream->dirty = 1;
        stream->deleted = 0;
    }

    {
        struct fd *fd = open_fd( NULL, stream->temp_name, nt_name, O_NONBLOCK, mode, access, sharing,
                                 options & ~FILE_DELETE_ON_CLOSE );
        if (fd)
        {
            struct file *file;
            obj = create_file_obj( fd, access, *mode );
            release_object( fd );
            if (obj)
            {
                file = (struct file *)obj;
                file->stream = stream;
                file->stream_delete = !!(options & FILE_DELETE_ON_CLOSE);
                stream->refs++;
            }
        }
    }

done:
    if (temp_fd != -1) close( temp_fd );
    if (temp_name)
    {
        unlink( temp_name );
        free( temp_name );
    }
    if (stream && !stream->refs && !obj) free_xattr_stream( stream );
    if (base_fd != -1) close( base_fd );
    free( value );
    free( xattr );
    free( base );
    return obj;
}

static struct object *create_file( struct fd *root, const char *nameptr, data_size_t len,
                                   struct unicode_str nt_name,
                                   unsigned int access, unsigned int sharing, int create,
                                   unsigned int options, unsigned int attrs,
                                   const struct security_descriptor *sd )
{
    struct object *obj = NULL;
    struct fd *fd;
    int flags;
    char *name;
    mode_t mode;

    if (!len || ((nameptr[0] == '/') ^ !root) || (nt_name.len && ((nt_name.str[0] == '\\') ^ !root)))
    {
        set_error( STATUS_OBJECT_PATH_SYNTAX_BAD );
        return NULL;
    }
    if (!(name = mem_alloc( len + 1 ))) return NULL;
    memcpy( name, nameptr, len );
    name[len] = 0;

    switch(create)
    {
    case FILE_CREATE:       flags = O_CREAT | O_EXCL; break;
    case FILE_OVERWRITE_IF: /* FIXME: the difference is whether we trash existing attr or not */
                            access |= FILE_WRITE_ATTRIBUTES;
    case FILE_SUPERSEDE:    flags = O_CREAT | O_TRUNC; break;
    case FILE_OPEN:         flags = 0; break;
    case FILE_OPEN_IF:      flags = O_CREAT; break;
    case FILE_OVERWRITE:    flags = O_TRUNC;
                            access |= FILE_WRITE_ATTRIBUTES; break;
    default:                set_error( STATUS_INVALID_PARAMETER ); goto done;
    }

    if (sd)
    {
        const struct sid *owner = sd_get_owner( sd );
        if (!owner)
            owner = token_get_owner( current->process->token );
        mode = sd_to_mode( sd, owner );
    }
    else if (options & FILE_DIRECTORY_FILE)
        mode = (attrs & FILE_ATTRIBUTE_READONLY) ? 0555 : 0777;
    else
        mode = (attrs & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666;

    if (is_file_executable( name ))
    {
        if (mode & S_IRUSR)
            mode |= S_IXUSR;
        if (mode & S_IRGRP)
            mode |= S_IXGRP;
        if (mode & S_IROTH)
            mode |= S_IXOTH;
    }

    access = map_access( access, &file_type.mapping );

    {
        int handled;

        obj = create_xattr_stream( root, name, nt_name, flags, &mode, access, sharing, options, &handled );
        if (handled) goto done;
    }

    /* FIXME: should set error to STATUS_OBJECT_NAME_COLLISION if file existed before */
    fd = open_fd( root, name, nt_name, flags | O_NONBLOCK, &mode, access, sharing, options );
    if (!fd) goto done;

    if (S_ISDIR(mode))
        obj = create_dir_obj( fd, access, mode );
    else if (S_ISCHR(mode) && is_serial_fd( fd ))
        obj = create_serial( fd );
    else
        obj = create_file_obj( fd, access, mode );

    release_object( fd );

done:
    free( name );
    return obj;
}

static void file_dump( struct object *obj, int verbose )
{
    struct file *file = (struct file *)obj;
    assert( obj->ops == &file_ops );
    fprintf( stderr, "File fd=%p\n", file->fd );
}

static enum server_fd_type file_get_fd_type( struct fd *fd )
{
    struct file *file = get_fd_user( fd );

    if (S_ISREG(file->mode) || S_ISBLK(file->mode)) return FD_TYPE_FILE;
    if (S_ISDIR(file->mode)) return FD_TYPE_DIR;
    return FD_TYPE_CHAR;
}

static struct fd *file_get_fd( struct object *obj )
{
    struct file *file = (struct file *)obj;
    assert( obj->ops == &file_ops );
    return (struct fd *)grab_object( file->fd );
}

struct security_descriptor *mode_to_sd( mode_t mode, const struct sid *user, const struct sid *group )
{
    struct security_descriptor *sd;
    unsigned char flags;
    size_t dacl_size;
    struct ace *ace;
    struct acl *dacl;
    char *ptr;

    dacl_size = sizeof(*dacl) + sizeof(*ace) + sid_len( &local_system_sid );
    if (mode & S_IRWXU) dacl_size += sizeof(*ace) + sid_len( user );
    if ((!(mode & S_IRUSR) && (mode & (S_IRGRP|S_IROTH))) ||
        (!(mode & S_IWUSR) && (mode & (S_IWGRP|S_IWOTH))) ||
        (!(mode & S_IXUSR) && (mode & (S_IXGRP|S_IXOTH))))
        dacl_size += sizeof(*ace) + sid_len( user );
    if (mode & S_IRWXO) dacl_size += sizeof(*ace) + sid_len( &world_sid );

    sd = mem_alloc( sizeof(*sd) + sid_len( user ) + sid_len( group ) + dacl_size );
    if (!sd) return sd;

    sd->control = SE_DACL_PRESENT;
    sd->owner_len = sid_len( user );
    sd->group_len = sid_len( group );
    sd->sacl_len = 0;
    sd->dacl_len = dacl_size;

    ptr = mem_append( sd + 1, user, sd->owner_len );
    ptr = mem_append( ptr, group, sd->group_len );

    dacl = (struct acl *)ptr;
    dacl->revision = ACL_REVISION;
    dacl->pad1     = 0;
    dacl->size     = dacl_size;
    dacl->count    = 1;
    dacl->pad2     = 0;
    if (mode & S_IRWXU) dacl->count++;
    if ((!(mode & S_IRUSR) && (mode & (S_IRGRP|S_IROTH))) ||
        (!(mode & S_IWUSR) && (mode & (S_IWGRP|S_IWOTH))) ||
        (!(mode & S_IXUSR) && (mode & (S_IXGRP|S_IXOTH))))
        dacl->count++;
    if (mode & S_IRWXO) dacl->count++;

    flags = (mode & S_IFDIR) ? OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE : 0;

    /* always give FILE_ALL_ACCESS for Local System */
    ace = set_ace( (struct ace *)(dacl + 1), &local_system_sid,
                   ACCESS_ALLOWED_ACE_TYPE, flags, FILE_ALL_ACCESS );

    if (mode & S_IRWXU)
    {
        /* appropriate access rights for the user */
        ace = set_ace( ace_next( ace ), user, ACCESS_ALLOWED_ACE_TYPE, flags, WRITE_DAC | WRITE_OWNER );
        if (mode & S_IRUSR) ace->mask |= FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        if (mode & S_IWUSR) ace->mask |= FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
    }
    if ((!(mode & S_IRUSR) && (mode & (S_IRGRP|S_IROTH))) ||
        (!(mode & S_IWUSR) && (mode & (S_IWGRP|S_IWOTH))) ||
        (!(mode & S_IXUSR) && (mode & (S_IXGRP|S_IXOTH))))
    {
        /* deny just in case the user is a member of the group */
        ace = set_ace( ace_next( ace ), user, ACCESS_DENIED_ACE_TYPE, flags, 0 );
        if (!(mode & S_IRUSR) && (mode & (S_IRGRP|S_IROTH)))
            ace->mask |= FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        if (!(mode & S_IWUSR) && (mode & (S_IWGRP|S_IROTH)))
            ace->mask |= FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
        ace->mask &= ~STANDARD_RIGHTS_ALL; /* never deny standard rights */
    }
    if (mode & S_IRWXO)
    {
        /* appropriate access rights for Everyone */
        ace = set_ace( ace_next( ace ), &world_sid, ACCESS_ALLOWED_ACE_TYPE, flags, 0 );
        if (mode & S_IROTH) ace->mask |= FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        if (mode & S_IWOTH) ace->mask |= FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
    }

    return sd;
}

static struct security_descriptor *file_get_sd( struct object *obj )
{
    struct file *file = (struct file *)obj;
    struct stat st;
    int unix_fd;
    struct security_descriptor *sd;

    assert( obj->ops == &file_ops );

    unix_fd = get_file_unix_fd( file );

    if (unix_fd == -1 || fstat( unix_fd, &st ) == -1)
        return obj->sd;

    /* mode and uid the same? if so, no need to re-generate security descriptor */
    if (obj->sd && (st.st_mode & (S_IRWXU|S_IRWXO)) == (file->mode & (S_IRWXU|S_IRWXO)) &&
        (st.st_uid == file->uid))
        return obj->sd;

    sd = mode_to_sd( st.st_mode,
                     security_unix_uid_to_sid( st.st_uid ),
                     token_get_primary_group( current->process->token ));
    if (!sd) return obj->sd;

    file->mode = st.st_mode;
    file->uid = st.st_uid;
    free( obj->sd );
    obj->sd = sd;
    return sd;
}

static mode_t file_access_to_mode( unsigned int access )
{
    mode_t mode = 0;

    access = map_access( access, &file_type.mapping );
    if (access & FILE_READ_DATA)  mode |= 4;
    if (access & (FILE_WRITE_DATA|FILE_APPEND_DATA)) mode |= 2;
    if (access & FILE_EXECUTE)    mode |= 1;
    return mode;
}

mode_t sd_to_mode( const struct security_descriptor *sd, const struct sid *owner )
{
    mode_t new_mode = 0;
    mode_t bits_to_set = ~0;
    mode_t mode;
    int present;
    const struct acl *dacl = sd_get_dacl( sd, &present );

    if (present && dacl)
    {
        const struct ace *ace = (const struct ace *)(dacl + 1);
        unsigned int i;

        for (i = 0; i < dacl->count; i++, ace = ace_next( ace ))
        {
            const struct sid *sid = (const struct sid *)(ace + 1);

            if (ace->flags & INHERIT_ONLY_ACE) continue;

            mode = file_access_to_mode( ace->mask );
            switch (ace->type)
            {
                case ACCESS_DENIED_ACE_TYPE:
                    if (equal_sid( sid, &world_sid ))
                    {
                        bits_to_set &= ~((mode << 6) | (mode << 3) | mode); /* all */
                    }
                    else if (token_sid_present( current->process->token, owner, TRUE ) &&
                             token_sid_present( current->process->token, sid, TRUE ))
                    {
                        bits_to_set &= ~((mode << 6) | (mode << 3));  /* user + group */
                    }
                    else if (equal_sid( sid, owner ))
                    {
                        bits_to_set &= ~(mode << 6);  /* user only */
                    }
                    break;
                case ACCESS_ALLOWED_ACE_TYPE:
                    if (equal_sid( sid, &world_sid ))
                    {
                        mode = (mode << 6) | (mode << 3) | mode;  /* all */
                        new_mode |= mode & bits_to_set;
                        bits_to_set &= ~mode;
                    }
                    else if (token_sid_present( current->process->token, owner, FALSE ) &&
                             token_sid_present( current->process->token, sid, FALSE ))
                    {
                        mode = (mode << 6) | (mode << 3);  /* user + group */
                        new_mode |= mode & bits_to_set;
                        bits_to_set &= ~mode;
                    }
                    else if (equal_sid( sid, owner ))
                    {
                        mode = (mode << 6);  /* user only */
                        new_mode |= mode & bits_to_set;
                        bits_to_set &= ~mode;
                    }
                    break;
            }
        }
    }
    else
        /* no ACL means full access rights to anyone */
        new_mode = S_IRWXU | S_IRWXG | S_IRWXO;

    return new_mode;
}

static int file_set_sd( struct object *obj, const struct security_descriptor *sd,
                        unsigned int set_info )
{
    struct file *file = (struct file *)obj;
    const struct sid *owner;
    struct stat st;
    mode_t mode;
    int unix_fd;

    assert( obj->ops == &file_ops );

    unix_fd = get_file_unix_fd( file );

    if (unix_fd == -1 || fstat( unix_fd, &st ) == -1) return 1;

    if (set_info & OWNER_SECURITY_INFORMATION)
    {
        owner = sd_get_owner( sd );
        if (!owner)
        {
            set_error( STATUS_INVALID_SECURITY_DESCR );
            return 0;
        }
        if (!obj->sd || !equal_sid( owner, sd_get_owner( obj->sd ) ))
        {
            /* FIXME: get Unix uid and call fchown */
        }
    }
    else if (obj->sd)
        owner = sd_get_owner( obj->sd );
    else
        owner = token_get_owner( current->process->token );

    /* group and sacl not supported */

    if (set_info & DACL_SECURITY_INFORMATION)
    {
        /* keep the bits that we don't map to access rights in the ACL */
        mode = st.st_mode & (S_ISUID|S_ISGID|S_ISVTX);
        mode |= sd_to_mode( sd, owner );

        if (((st.st_mode ^ mode) & (S_IRWXU|S_IRWXG|S_IRWXO)) && fchmod( unix_fd, mode ) == -1)
        {
            file_set_error();
            return 0;
        }
    }
    return 1;
}

static struct object *file_lookup_name( struct object *obj, struct unicode_str *name,
                                        unsigned int attr, struct object *root )
{
    if (!name || !name->len) return NULL;  /* open the file itself */

    set_error( STATUS_OBJECT_PATH_NOT_FOUND );
    return NULL;
}

static struct object *file_open_file( struct object *obj, unsigned int access,
                                      unsigned int sharing, unsigned int options )
{
    struct file *file = (struct file *)obj;
    struct object *new_file = NULL;
    char *unix_name;

    assert( obj->ops == &file_ops );

    if ((unix_name = dup_fd_name( file->fd, "" )))
    {
        new_file = create_file( NULL, unix_name, strlen(unix_name), get_nt_name(file->fd), access,
                                sharing, FILE_OPEN, options, 0, NULL );
        free( unix_name );
    }
    else set_error( STATUS_OBJECT_TYPE_MISMATCH );
    return new_file;
}

static struct list *file_get_kernel_obj_list( struct object *obj )
{
    struct file *file = (struct file *)obj;
    return &file->kernel_object;
}

static void file_destroy( struct object *obj )
{
    struct file *file = (struct file *)obj;
    assert( obj->ops == &file_ops );

    if (file->stream)
    {
        struct xattr_stream *stream = file->stream;

        if (get_fd_disposition( file->fd ) & FILE_DISPOSITION_DELETE) file->stream_delete = 1;
        clear_fd_disposition( file->fd );  /* never unlink the server's shared backing file */
        if (file->access & (FILE_WRITE_DATA | FILE_APPEND_DATA)) stream->dirty = 1;
        if (file->stream_delete)
        {
            stream->deleted = 1;
            stream->dirty = 0;
        }
        if ((stream->dirty || stream->deleted) && sync_xattr_stream( stream ) == -1 &&
            !(stream->deleted && (errno == ENODATA || errno == ENOENT)))
            fprintf( stderr, "wineserver: failed to save xattr stream %s: %s\n",
                     stream->xattr_name, strerror(errno) );
        else stream->dirty = 0;
        if (!--stream->refs) free_xattr_stream( stream );
    }

    if (file->fd) release_object( file->fd );
}

/* set the last error depending on errno */
void file_set_error(void)
{
    switch (errno)
    {
    case ETXTBSY:
    case EAGAIN:    set_error( STATUS_SHARING_VIOLATION ); break;
    case EBADF:     set_error( STATUS_INVALID_HANDLE ); break;
    case ENOSPC:    set_error( STATUS_DISK_FULL ); break;
    case EACCES:
    case ESRCH:
    case EROFS:
    case EPERM:     set_error( STATUS_ACCESS_DENIED ); break;
    case EBUSY:     set_error( STATUS_FILE_LOCK_CONFLICT ); break;
    case ENOENT:    set_error( STATUS_NO_SUCH_FILE ); break;
    case EISDIR:    set_error( STATUS_FILE_IS_A_DIRECTORY ); break;
    case ENFILE:
    case EMFILE:    set_error( STATUS_TOO_MANY_OPENED_FILES ); break;
    case EEXIST:    set_error( STATUS_OBJECT_NAME_COLLISION ); break;
    case EINVAL:    set_error( STATUS_INVALID_PARAMETER ); break;
    case ESPIPE:    set_error( STATUS_ILLEGAL_FUNCTION ); break;
    case ENOTEMPTY: set_error( STATUS_DIRECTORY_NOT_EMPTY ); break;
    case EIO:       set_error( STATUS_ACCESS_VIOLATION ); break;
    case ENOTDIR:   set_error( STATUS_NOT_A_DIRECTORY ); break;
    case EFBIG:     set_error( STATUS_SECTION_TOO_BIG ); break;
    case ENODEV:    set_error( STATUS_NO_SUCH_DEVICE ); break;
    case ENXIO:     set_error( STATUS_NO_SUCH_DEVICE ); break;
    case EXDEV:     set_error( STATUS_NOT_SAME_DEVICE ); break;
    case ELOOP:     set_error( STATUS_REPARSE_POINT_NOT_RESOLVED ); break;
#ifdef EOVERFLOW
    case EOVERFLOW: set_error( STATUS_INVALID_PARAMETER ); break;
#endif
    default:
        perror("wineserver: file_set_error() can't map error");
        set_error( STATUS_UNSUCCESSFUL );
        break;
    }
}

struct file *get_file_obj( struct process *process, obj_handle_t handle, unsigned int access )
{
    return (struct file *)get_handle_obj( process, handle, access, &file_ops );
}

int get_file_unix_fd( struct file *file )
{
    return get_unix_fd( file->fd );
}

/* create a file */
DECL_HANDLER(create_file)
{
    struct object *file;
    struct fd *root_fd = NULL;
    struct object_params params;
    const char *name;
    data_size_t name_len;

    if (!get_req_object_attributes( &params )) return;
    if (params.root) release_object( params.root );

    if (params.objattr->rootdir)
    {
        struct dir *root;

        if (!(root = get_dir_obj( current->process, params.objattr->rootdir, 0 ))) return;
        root_fd = get_obj_fd( (struct object *)root );
        release_object( root );
        if (!root_fd) return;
    }

    name = get_req_data_after_objattr( &params, &name_len );

    reply->handle = 0;
    if ((file = create_file( root_fd, name, name_len, params.name, req->access, req->sharing,
                             req->create, req->options, req->attrs, params.sd )))
    {
        reply->handle = alloc_handle( current->process, file, req->access, params.attr );
        release_object( file );
    }
    if (root_fd) release_object( root_fd );
}

/* allocate a file handle for a Unix fd */
DECL_HANDLER(alloc_file_handle)
{
    struct file *file;
    int fd;

    reply->handle = 0;
    if ((fd = thread_get_inflight_fd( current, req->fd )) == -1)
    {
        set_error( STATUS_INVALID_HANDLE );
        return;
    }
    if ((file = create_file_for_fd( fd, req->access, FILE_SHARE_READ | FILE_SHARE_WRITE )))
    {
        reply->handle = alloc_handle( current->process, file, req->access, req->attributes );
        release_object( file );
    }
}

/* lock a region of a file */
DECL_HANDLER(lock_file)
{
    struct file *file;

    if ((file = get_file_obj( current->process, req->handle, 0 )))
    {
        reply->handle = lock_fd( file->fd, req->offset, req->count, req->shared, req->wait );
        reply->overlapped = is_fd_overlapped( file->fd );
        release_object( file );
    }
}

/* unlock a region of a file */
DECL_HANDLER(unlock_file)
{
    struct file *file;

    if ((file = get_file_obj( current->process, req->handle, 0 )))
    {
        unlock_fd( file->fd, req->offset, req->count );
        release_object( file );
    }
}
