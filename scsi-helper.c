/*
 * Copyright (C) 2018 China Mobile Communications Corporation
 *
 * Author: Yaowei Bai <baiyaowei@cmss.chinamobile.com>
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

/* NOTE: need take care of CDB ALLOCATION LENGTH */

#include <stdio.h>
#include <dirent.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <glib.h>
#include <glib-unix.h>
#include <gio/gio.h>
#include <scsi/scsi.h>
#include <stdbool.h>

#include "libtcmu2.h"

int libtcmu2_set_sense(uint8_t *sense, uint8_t key, uint16_t asc_ascq)
{
    memset(sense, 0, 18);

    sense[0] = 0x70; /* error type: current
                        sense data format: fixed */
    sense[2] = key;
    sense[7] = 0xa; /* 17 -7 */
    sense[12] = (asc_ascq >> 8) & 0xff;
    sense[13] = asc_ascq & 0xff;

    return CHECK_CONDITION;
}

static int copy_into_vec(struct iovec *iovec, uint32_t iov_cnt,
                                    uint8_t *src, int len)
{
    int i, copied = 0;

    for(i = 0; i < iov_cnt; i++) {
        if(iovec[i].iov_len < len) {
            memcpy(iovec[i].iov_base, src, iovec[i].iov_len);
            len -= iovec[i].iov_len;
            src += iovec[i].iov_len;
            copied += iovec[i].iov_len;
        } else {
            memcpy(iovec[i].iov_base, src, len);
            copied += len;
            break;
        }
    }

    return copied;
}

int libtcmu2_emulate_inquiry(uint8_t *cdb, struct iovec *iovec,
                              uint32_t iov_cnt, uint8_t *sense)
{
    if(cdb[1] & 0x01) {
       /* VPD page inquiry */
       switch(cdb[2]) {
       case 0x00: /* Supported VPD Pages, Mandatory */
       {
           uint8_t buf[5];

           memset(buf, 0, sizeof(buf));

           buf[0] = 0x00;
           buf[1] = 0x00; /* page code */
           buf[2] = 0x00;
           buf[3] = 1; /* 4 - 3 */
           buf[4] = 0x00; /* this page */
           copy_into_vec(iovec, iov_cnt, buf, sizeof(buf));
           break;
       }
       default:
           libtcmu2_set_sense(sense, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB);
           return CHECK_CONDITION;
       }
    } else {
        /* starndard inquiry */
        uint8_t buf[36]; /* at least 36 bytes according to SPC-4*/

        memset(buf, 0, sizeof(buf));

        buf[0] = 0x00; /* SBC-3 */
        buf[1] = 0x00; /* not removable */
        buf[2] = 0x06; /* SPC-4 */
        buf[3] = 0x02; /* RESPONSE DATA FORMAT, not support
                          hierarchical addressing model */
        buf[4] = 31; /* 35 - 4 */
        buf[5] = 0x00; /* nut support ALUA and Third-Party Copy (3PC)
                          currently */
        buf[6] = 0x00; /* not support multi port */
        buf[7] = 0x00; /* not support command management model */
        memcpy(&buf[8], "TCMU", 4);
        memcpy(&buf[16], "libtcmu2", 8);
        memcpy(&buf[32], "v2", 2);
        copy_into_vec(iovec, iov_cnt, buf, 36);
    }

    return GOOD;
}

int libtcmu2_emulate_test_unit_ready(uint8_t *cdb, struct iovec *vec,
                                     uint32_t vec_cnt, uint8_t *sense)
{
     return GOOD;
}

int libtcmu2_emulate_read_capacity_16(uint64_t num_lbas, uint32_t block_size,
                                      uint8_t *cdb, struct iovec *iovec,
                                      size_t iov_cnt, uint8_t *sense)
{
    uint8_t buf[32];
    uint64_t val64;
    uint32_t val32;

    memset(buf, 0, sizeof(buf));

    val64 = htobe64(num_lbas-1);
    memcpy(&buf[0], &val64, 8);

    val32 = htobe32(block_size);
    memcpy(&buf[8], &val32, 4);

    copy_into_vec(iovec, iov_cnt, buf, sizeof(buf));

    return GOOD;
}
