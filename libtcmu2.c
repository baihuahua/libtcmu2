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

#define _BITS_UIO_H
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

#include "libtcmu2.h"
#include "target_core_user.h"
#include "../tcmuhandler-generated.h"

void libtcmu2_close_device(struct tcmu_device *tdev)
{
    munmap(tdev->mmap, tdev->mmap_size);
    close(tdev->fd);
    free(tdev);
}

struct tcmu_device *libtcmu2_open_device(const char *cfgstr)
{
    struct tcmu_device *tdev;
    DIR *tdir;
    struct dirent *tdirent;
    int i, fcnt = 0;
    int fd, ret;
    char buf[128];

    tdev = calloc(1, sizeof(*tdev));
    if(!tdev) {
        printf("alloc tcmu_device failed.\n");
        return NULL;
    }

    tdir = opendir("/sys/class/uio/");
    if(tdir == NULL) {
        printf("open dir failed.\n");
        goto err_free;
    }
    for(tdirent = readdir(tdir); tdirent != NULL; tdirent = readdir(tdir))
        fcnt++;
    closedir(tdir);
    fcnt = fcnt - 2; /* drop "." and ".." */

    for(i = 0; i < fcnt; i++) {
        char *ptr, *oldptr;
        int len;
        char hba_buf[TCMU_DEVICE_HBA_SIZE];
        char dev_buf[TCMU_DEVICE_NAME_SIZE];
        char cfgstr_buf[TCMU_DEVICE_CFGSTR_SIZE];

        snprintf(buf, sizeof(buf), "/sys/class/uio/uio%d/name", i);
        fd = open(buf, O_RDONLY);
        ret = read(fd, buf, sizeof(buf));
        close(fd);
        if(ret <= 0) {
            printf("read uio name file failed.\n");
            goto err_free;
        }
        buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

        oldptr = buf;
        ptr = strchr(oldptr, '/');
        if (!ptr) {
            printf("invalid uio name.\n");
            goto err_free;
        }

        if (strncmp(buf, "tcm-user", ptr-oldptr)) {
            continue;
        }

        /* 1/3: HBA index */
        oldptr = ptr+1;
        ptr = strchr(oldptr, '/');
        if (!ptr) {
            printf("invalid uio name.\n");
            goto err_free;
        }
        len = ptr-oldptr;
        snprintf(hba_buf, sizeof(hba_buf), "%.*s", len, oldptr);

        /* 2/3: device name */
        oldptr = ptr+1;
        ptr = strchr(oldptr, '/');
        if (!ptr) {
            printf("invalid uio name.\n");
            goto err_free;
        }
        len = ptr-oldptr;
        snprintf(dev_buf, sizeof(dev_buf), "%.*s", len, oldptr);

        /* 3/3: cfgstring */
        oldptr = ptr+1;
        snprintf(cfgstr_buf, sizeof(cfgstr_buf), "%s", oldptr);

        if (!strcmp(cfgstr_buf, cfgstr)) {
            strcpy(tdev->hba_index, hba_buf);
            strcpy(tdev->name, dev_buf);
            strcpy(tdev->cfgstr, cfgstr_buf);
            break;
        }
    }
    if (i == fcnt) {
        printf("find uio device failed.\n");
        goto err_free;
    }

    /* mmap for user */
    /* 1/3: open udev */
    snprintf(buf, sizeof(buf), "/dev/uio%s", tdev->hba_index);
    tdev->fd = open(buf, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if(tdev->fd == -1) {
        printf("open udev device failed.\n");
        goto err_free;
    }

    /* 2/3: mmap size */
    snprintf(buf, sizeof(buf), "/sys/class/uio/uio%s/maps/map0/size", tdev->hba_index);
    fd = open(buf, O_RDONLY);
    if(fd == -1) {
        printf("open udev map size file failed.\n");
        goto err_udev_close;
    }
    ret = read(fd, buf, sizeof(buf));
    close(fd);
    if(ret <= 0) {
        printf("read udev map size file failed.\n");
        goto err_udev_close;
    }
    buf[ret-1] = '\0';
    tdev->mmap_size = strtoull(buf, NULL, 0);

    /* 3/3: mmap */
    tdev->mmap = mmap(NULL, tdev->mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, tdev->fd, 0);
    if(tdev->mmap == MAP_FAILED) {
        printf("mmap failed.\n");
        goto err_udev_close;
    }
    tdev->cmd_tail = tdev->mmap->cmd_tail;
    return tdev;

err_udev_close:
    close(tdev->fd);
err_free:
    free(tdev);

    return NULL;
}

static gboolean libtcmu2_dbus_close_device(TCMUService1 *interface,
                                      GDBusMethodInvocation *invocation,
                                      gchar *name, gpointer arg)
{
    struct libtcmu2_handler *handler = arg;
    bool ret = TRUE;

    if (handler->close_device)
        ret = handler->close_device(name);

    g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", ret));

    return TRUE;
}

static gboolean libtcmu2_dbus_open_device(TCMUService1 *interface,
                                      GDBusMethodInvocation *invocation,
                                      gchar *cfgstr, gpointer arg)
{
    struct libtcmu2_handler *handler = arg;
    bool ret = TRUE;

    if (handler->open_device)
        ret = handler->open_device(cfgstr);

    g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", ret));

    return TRUE;
}

static gboolean libtcmu2_dbus_check_config(TCMUService1 *interface,
                                      GDBusMethodInvocation *invocation,
                                      gchar *cfgstr, gpointer arg)
{
    struct libtcmu2_handler *handler = arg;
    bool ret = TRUE;

    if (handler->check_config)
        ret = handler->check_config(cfgstr);

    g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", ret));

    return TRUE;
}

static GDBusObjectManagerServer *manager;

static void libtcmu2_dbus_acquired(GDBusConnection *connection, const gchar *name,
                                   gpointer arg)
{
    struct libtcmu2_handler *handler = arg;
    GDBusObjectSkeleton *object;
    TCMUService1 *interface;
    char obj_name[128];

    manager = g_dbus_object_manager_server_new("/org/kernel/TCMUService1");

    snprintf(obj_name, sizeof(obj_name), "/org/kernel/TCMUService1/%s", handler->subtype);
    object = g_dbus_object_skeleton_new(obj_name);
    interface = tcmuservice1_skeleton_new();
    g_dbus_object_skeleton_add_interface(object, G_DBUS_INTERFACE_SKELETON(interface));

    g_signal_connect(interface, "handle-check-config", G_CALLBACK(libtcmu2_dbus_check_config),
                     handler);
    g_signal_connect(interface, "handle-open-device", G_CALLBACK(libtcmu2_dbus_open_device),
                     handler);
    g_signal_connect(interface, "handle-close-device", G_CALLBACK(libtcmu2_dbus_close_device),
                     handler);

    g_dbus_object_manager_server_export(manager, G_DBUS_OBJECT_SKELETON(object));
    g_dbus_object_manager_server_set_connection(manager, connection);

    g_object_unref(object);
}

#define TCMU_DBUS_NAME "org.kernel.TCMUService1"

/* TODO:only support one handler in system scope at the same time because of dbus
 *      service name own
 */
void libtcmu2_register_handler(struct libtcmu2_handler *handler)
{
    /* an identifier (never 0) that an be used with g_bus_unown_name() to stop owning the name.*/
    g_bus_own_name(G_BUS_TYPE_SYSTEM, TCMU_DBUS_NAME, G_BUS_NAME_OWNER_FLAGS_NONE,
                   libtcmu2_dbus_acquired, NULL, NULL, handler, NULL);
}

int libtcmu2_get_cdb_length(uint8_t *cdb)
{
    switch (cdb[0] >> 5) {
    case 0:
        return 6;
    case 1:
    case 2:
        return 10;
    case 4:
        return 16;
    case 5:
        return 12;
    default:
        return -1;
    }
}

uint64_t libtcmu2_get_lba(uint8_t *cdb)
{
    uint16_t val;

    switch (cdb[0] >> 5) {
    case 0:
        val = be16toh(*((uint16_t *)&cdb[2]));
        return ((cdb[1] & 0x1f) << 16) | val;
    case 1:
    case 2:
    case 5:
        return be32toh(*((u_int32_t *)&cdb[2]));
    case 4:
        return be64toh(*((u_int64_t *)&cdb[2]));
    default:
        return 0;
    }
}

#define RB_CMD_TAIL(tdev) (struct tcmu_cmd_entry *) ((char *) tdev->mmap + \
                                tdev->mmap->cmdr_off + tdev->mmap->cmd_tail)
#define RB_CMD_HEAD(tdev) (struct tcmu_cmd_entry *) ((char *) tdev->mmap + \
                                tdev->mmap->cmdr_off + tdev->mmap->cmd_head)
#define DEV_CMD_TAIL(tdev) (struct tcmu_cmd_entry *) ((char *) tdev->mmap + \
                                       tdev->mmap->cmdr_off + tdev->cmd_tail)

#define UPDATE_DEV_CMD_TAIL(tdev, ent) \
do { \
    tdev->cmd_tail = (tdev->cmd_tail + tcmu_hdr_get_len((ent)->hdr.len_op)) % \
                                            tdev->mmap->cmdr_size; \
} while (0)

struct scsi_cmd *libtcmu2_get_scsi_command(struct tcmu_device *tdev)
{
    struct tcmu_cmd_entry *ent;
    struct scsi_cmd *cmd;
    uint8_t *cdb;
    int cdb_len, i;

    while ((ent = DEV_CMD_TAIL(tdev)) != RB_CMD_HEAD(tdev)) {
        UPDATE_DEV_CMD_TAIL(tdev, ent);
        int op = tcmu_hdr_get_op(ent->hdr.len_op);

        if(op == TCMU_OP_CMD) {
            break;
        } else if(op != TCMU_OP_PAD)
            ent->hdr.uflags |= TCMU_UFLAG_UNKNOWN_OP;
    }

    if(ent == RB_CMD_HEAD(tdev))
        return NULL;

    cdb = (uint8_t *) tdev->mmap + ent->req.cdb_off;
    cdb_len = libtcmu2_get_cdb_length(cdb);

    cmd = malloc(sizeof(*cmd) + sizeof(*cmd->iovec) * ent->req.iov_cnt + cdb_len);
    if (!cmd)
         return NULL;

    cmd->cmd_id = ent->hdr.cmd_id;
    cmd->iov_cnt = ent->req.iov_cnt;
    cmd->iovec = (struct iovec *) (cmd + 1);
    cmd->cdb = (uint8_t *) (cmd->iovec + cmd->iov_cnt);
    memcpy(cmd->cdb, cdb, cdb_len);
    for (i = 0; i < ent->req.iov_cnt; i++) {
        cmd->iovec[i].iov_base = (void *) tdev->mmap +
                                 (size_t) ent->req.iov[i].iov_base;
        cmd->iovec[i].iov_len = ent->req.iov[i].iov_len;
    }

    return cmd;
}

#define UPDATE_RB_CMD_TAIL(tdev, ent) \
do { \
    tdev->mmap->cmd_tail = (tdev->mmap->cmd_tail + \
                    tcmu_hdr_get_len((ent)->hdr.len_op)) % tdev->mmap->cmdr_size; \
} while (0)

void libtcmu2_complete_scsi_command(struct tcmu_device *tdev, struct scsi_cmd *cmd)
{
    struct tcmu_cmd_entry *ent;

    /* reuse ringbuffer to store completed command, should always get a reuseable entry */
    while ((ent = RB_CMD_TAIL(tdev)) != RB_CMD_HEAD(tdev)) {
        UPDATE_RB_CMD_TAIL(tdev, ent);
        if (tcmu_hdr_get_op(ent->hdr.len_op) == TCMU_OP_CMD)
            break;
    }

    ent->hdr.cmd_id = cmd->cmd_id;
    ent->rsp.scsi_status = cmd->result;
    if (cmd->result != GOOD) {
        memcpy(ent->rsp.sense_buffer, cmd->sense, TCMU_SENSE_BUFFERSIZE);
    }

    free(cmd);
}

void libtcmu2_process_scsi_prepare(struct tcmu_device *tdev)
{
    int ret;
    uint32_t buf;

    do {
        ret = read(tdev->fd, &buf, 4);
    } while (ret == -1);
}

void libtcmu2_process_scsi_done(struct tcmu_device *tdev)
{
    int ret;
    uint32_t buf = 0;

    do {
        ret = write(tdev->fd, &buf, 4);
    } while (ret == -1);
}
