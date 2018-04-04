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

int libtcmu2_emulate_inquiry(uint8 *cdb,vec,vec_cnt,sense)
{
    int ret;

    if(cdb[1] & 0x01) {
       /* VPD page inquiry */
       switch(cdb[2]) {
       case 0x00: /* Supported VPD Pages, Mandatory */
       {
           char buf[6];
           memset(buf, 0, 6);
           buf[0] = 0x00;
           buf[1] = 0x00; /* page code */
           buf[2] = 0x00;
           buf[3] = 2; /* 5 - 3 */
           buf[4] = 0x00; /* this page */
           buf[5] = 0x83; /* Device Identification */
           copy_into_vec(vec, vec_cnt, buf, 6);
           break;
       }
       case 0x83: /* Device Identification, Mandatory */
       {
           char
       default:
    } else {
        /* starndard inquiry */
        char buf[36]; /* at least 36 bytes according to SPC-4*/
        memset(buf, 0, 36);

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
        copy_into_vec(vec, vec_cnt, buf, 36);
    }
}
