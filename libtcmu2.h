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

struct libtcmu2_handler {
    bool (*check_cfgstr)(const char *cfgstr);
    int (*handle_scsi)(struct tcmu_device *dev, uint8_t *cdb,
                    struct iovec *iovec, size_t iov_cnt, uint8_t *sense)
    struct nl_sock *sock;
    u32 sock_fd;
    QLIST_HEAD(, tcmu_device) devices;

    int (*add_device)(struct tcmu_device *dev);
    void (*remove_device)(struct tcmu_device *dev);
    const char *subtype;
}

struct tcmu_device {
    u32 fd;
    struct tcmu_mailbox *map;
    struct libtcmu2_handler *handler;
    QLIST_ENTRY(tcmu_device) list; /* handler->devices */
}

int libtcmu2_register_handler(struct libtcmu2_handler *handler);
void libtcmu2_process_dev_ringbuffer(struct tcmu_device *tdev);
