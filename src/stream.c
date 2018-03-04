/*
   Stream reader

   (c) 2008 Jindrich Makovicka (makovick@gmail.com)

   This file is part of NFblockD.

   NFblockD is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   NFblockD is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Emacs; see the file COPYING.  If not, write to
   the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.
*/

#include "stream.h"
#include "nfblockd.h"
#include <errno.h>
#include <string.h>
#include <syslog.h>

#ifdef HAVE_ZLIB
int
stream_open(stream_t* stream, const char* filename)
{
    int l = strlen(filename);
    if (l >= 3 && strcmp(filename + l - 3, ".gz") == 0) {
        stream->f = fopen(filename, "r");
        if (!stream->f) {
            do_log(LOG_INFO, "Cannot open file %s: %s",
                filename, strerror(errno));
            return -1;
        }
        stream->compressed = 1;
        stream->strm.zalloc = Z_NULL;
        stream->strm.zfree = Z_NULL;
        stream->strm.opaque = Z_NULL;
        stream->strm.avail_in = 0;
        stream->strm.next_in = Z_NULL;
        if (inflateInit2(&stream->strm, 47) != Z_OK) {
            do_log(LOG_INFO, "Cannot initialize zLib");
            return -1;
        }
        stream->strm.avail_out = CHUNK;
        stream->strm.next_out = stream->out;
        stream->eos = 0;
    } else {
        stream->compressed = 0;
        stream->f = fopen(filename, "r");
        if (!stream->f) {
            do_log(LOG_INFO, "Cannot open file %s: %s",
                filename, strerror(errno));
            return -1;
        }
    }
    return 0;
}

int
stream_close(stream_t* stream)
{
    if (stream->compressed) {
        if (!stream->eos) {
            inflateEnd(&stream->strm);
        }
        if (fclose(stream->f) < 0) {
            do_log(LOG_INFO, "Error closing file: %s", strerror(errno));
            return -1;
        }
    } else {
        if (fclose(stream->f) < 0) {
            do_log(LOG_INFO, "Error closing file: %s", strerror(errno));
            return -1;
        }
    }
    return 0;
}

char*
stream_getline(char* buf, int max, stream_t* stream)
{
    if (stream->compressed) {
        int ret, avail;
        unsigned char* ptr;
        if (!stream->eos && stream->strm.avail_out) {
            do {
                if (stream->strm.avail_in == 0) {
                    stream->strm.avail_in = fread(stream->in, 1,
                        CHUNK, stream->f);
                    if (stream->strm.avail_in == 0) {
                        if (ferror(stream->f))
                            do_log(LOG_INFO, "Error reading file");
                        stream->eos = 1;
                        inflateEnd(&stream->strm);
                        break;
                    }
                    stream->strm.next_in = stream->in;
                }

                ret = inflate(&stream->strm, Z_NO_FLUSH);
                switch (ret) {
                case Z_STREAM_END:
                    stream->eos = 1;
                    inflateEnd(&stream->strm);
                    goto out;
                case Z_NEED_DICT:
                    ret = Z_DATA_ERROR; /* and fall through */
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    do_log(LOG_INFO, "Error during decompression");
                    stream->eos = 1;
                    inflateEnd(&stream->strm);
                    goto out;
                default:
                    break;
                }
            } while (stream->strm.avail_out);
        }

    out:

        avail = CHUNK - stream->strm.avail_out;
        ptr = memchr(stream->out, '\n', avail);
        // handle lines is longer than the maximum
        if (!ptr && avail > max - 1)
            ptr = stream->out + max - 1;
        // handle missing LF at the end of file
        if (!ptr && avail && stream->eos)
            ptr = stream->out + avail - 1;
        // now, ptr should point to the last character copied, if there is any
        if (ptr) {
            int copied = ptr - stream->out + 1;
            if (copied >= max - 1)
                copied = max - 1;
            memcpy(buf, stream->out, copied);
            buf[copied] = 0;

            memmove(stream->out, stream->out + copied, avail - copied);
            stream->strm.avail_out += copied;
            stream->strm.next_out -= copied;
            return buf;
        }
        return NULL;
    } else {
        char* ret;
        ret = fgets(buf, max, stream->f);
        if (!ret && ferror(stream->f))
            do_log(LOG_INFO, "Error reading file");
        return ret;
    }
}

#else /* !HAVE_ZLIB */

int
stream_open(stream_t* stream, const char* filename)
{
    stream->f = fopen(filename, "r");

    if (!stream->f) {
        do_log(LOG_INFO, "Cannot open file %s: %s",
            filename, strerror(errno));
        return -1;
    }

    return 0;
}

int
stream_close(stream_t* stream)
{
    if (fclose(stream->f) < 0) {
        do_log(LOG_INFO, "Error closing file: %s", strerror(errno));
        return -1;
    }

    return 0;
}

char*
stream_getline(char* buf, int max, stream_t* stream)
{
    char* ret;
    ret = fgets(buf, max, stream->f);
    if (!ret)
        do_log(LOG_INFO, "Error reading file");
    return ret;
}

#endif
