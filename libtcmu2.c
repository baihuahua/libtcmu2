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

/* http://www.infradead.org/~tgr/libnl/doc/core.html */

static struct nla_policy tcmu_policy[TCMU_ATTR_MAX+1] = {
    [TCMU_ATTR_DEVICE]      = { .type = NLA_STRING },
    [TCMU_ATTR_MINOR]       = { .type = NLA_U32 },
    [TCMU_ATTR_DEVICE_ID]   = { .type = NLA_U32 },
};
/* netlink/genl/mngt.h */
static struct genl_cmd tcmu_cmds[] = {
    {
        .c_id           = TCMU_CMD_ADDED_DEVICE,
        .c_name         = "ADDED DEVICE",
        .c_maxattr      = TCMU_ATTR_MAX,
        .c_attr_policy  = tcmu_policy,
        .c_msg_parser   = tcmu_parse_genl_msg,
    },
    {
        .c_id           = TCMU_CMD_REMOVED_DEVICE,
        .c_name         = "REMOVED DEVICE",
        .c_maxattr      = TCMU_ATTR_MAX,
        .c_attr_policy  = tcmu_policy,
        .c_msg_parser   = tcmu_parse_genl_msg,
    },
};

static struct genl_ops tcmu_ops = {
    .o_name         = "TCM-USER",
    .o_cmds         = tcmu_cmds,
    .o_ncmds        = ARRAY_SIZE(tcmu_cmds),
};

static gboolean libtcmu2_check_config(TCMUService1 *interface,
                                      GDBusMethodInvocation *invocation,
                                      gchar *cfgstr, gpointer arg)
{
    struct libtcmu2_handler *handler = arg;
    bool ret = TRUE;

    if (handler->check_cfgstr)
        ret = handler->check_cfgstr(cfgstr);

    g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", ret);

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
    g_signal_connect(interface, "handle-check-cfgstr", G_CALLBACK(libtcmu2_check_cfgstr),
                     handler);

    g_dbus_object_manager_server_export(manager, G_DBUS_OBJECT_SKELETON(object));
    g_dbus_object_manager_server_set_connection(manager, connection);

    g_object_unref(object);
}

$define TCMU_DBUS_NAME "org.kernel.TCMUService1"
#define TCMU_GENL_FAMILY "TCM-USER"
#define TCMU_NL_MULTICAST_GROUP "config"

/* TODO:only support one handler in system scope at the same time because of dbus
        service name own

 * own dbus and prepare netlink
 */
int libtcmu2_register_handler(struct libtcmu2_handler *handler)
{
    uint id;
    int ret;

    /* an identifier (never 0) that an be used with g_bus_unown_name() to stop owning the name.*/
    id = g_bus_own_name(G_BUS_TYPE_SYSTEM, TCMU_DBUS_NAME, G_BUS_NAME_OWNER_FLAGS_NONE,
                   libtcmu2_dbus_acquired, NULL, NULL, handler, NULL);

    sock = nl_socket_alloc();
    if (!sock) {
        printf("alloc netlink socket failed.\n");
        goto error_unown;
    }

    nl_socket_disable_seq_check(sock);
    ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, handler);
    if (ret < 0) {
        printf("modify callback failed.\n");
        goto error_free;
    }
    ret = genl_connect(sock);
    if (ret < 0) {
        printf("genl connect failed.\n");
        goto error_free;
    }

    ret = genl_register_family(&tcmu_ops);
    if (ret < 0) {
        printf("genl register family failed.\n");
        goto error_close;
    }

    ret = genl_ops_resolve(sock, &tcmu_ops);
    if (ret < 0) {
        printf("please modprobe target_core_user.\n");
        goto error_unregister;
    }

    ret = genl_ctrl_resolve_grp(sock, TCMU_GENL_FAMILY, TCMU_NL_MULTICAST_GROUP);
    if (ret < 0) {
        printf("resolve netlink multicast group failed.\n");
        goto error_unregister;
    }
    ret = nl_socket_add_membership(sock, ret);
    if (ret < 0) {
        printf("add netlink multicast group membership failed.\n");
        goto error_unregister;
    }

    handler->sock = sock;
    handler->sock_fd = nl_socket_get_fd(handler->sock);
    return 0;

error_unregister:
    genl_unregister_family(&tcmu_ops);
error_close:
    nl_close(sock);
error_free:
    nl_socket_free(sock);
error_unown:
    g_bus_unown_name(id);

    return -1;
}

static int remove_device(u32 minor, struct libtcmu2_handler *handler)
{

}

static int add_device(u32 minor, struct libtcmu2_handler *handler)
{
    struct tcmu_device *tdev;
    char *buf[64];
    int fd, ret, mmap_size;

    tdev = calloc(1, sizeof(*tdev));
    if (!tdev) {
        printf("alloc tcmu_device failed.\n");
        return -1;
    }

    /* mmap for user */
    /* 1. open udev */
    snprintf(buf, size_of(buf), "/dev/uio%d", minor);
    tdev->fd = open(buf, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if(tdev->fd == -1) {
        printf("open udev device failed.\n");
        goto error_free;
    }

    /* 2. mmap size */
    snprintf(buf, size_of(buf), "/sys/class/uio/uio%d/maps/map0/size", minor);
    fd = open(buf, O_RDONLY);
    if(fd == -1) {
        printf("open udev map size file failed.\n");
        goto error_udev_close;
    }
    ret = read(fd, buf, size_of(buf));
    close(fd);
    if(ret <= 0) {
        printf("read udev map size file failed.\n");
        goto error_udev_close;
    }
    buf[ret-1] = '\0';
    mmap_size = strtoull(buf, NULL, 0);

    /* 3. mmap */
    tdev->mmap = mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, tdev->fd, 0);
    if(tdev->mmap == MAP_FAILED) {
        printf("mmap failed.\n");
        goto error_udev_close;
    }

    list_add(handler->dev_list, tdev);
    tdev->handler = handler;

    if(handler->add_device) {
        ret = handler->add_device(tdev); 
        if(ret < 0) {
            printf("handler add device failed.\n");
            goto error_munmap;
        }
    }

    return 0;

error_munmap:
    munmap(tdev->map, mmap_size);
error_udev_close:
    close(tdev->fd);
error_free:
    free(tdev);

    return -1;
}

static int netlink_reply(u32 dev_id, int reply, struct libtcmu2_handler *handler,
                         int status)
{
    struct nl_msg *msg;

    msg = nlmsg_alloc();
    if(msg == NULL) {
        printf("netlink msg alloc failed.\n");
        return -1;
    }

    /* o_id is netlink family numeric identifier, automatically filled in
       by genl_ops_resolve() */
    if(genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, tcmu_ops.o_id,
                   0, 0, reply, 0) == NULL) {
        printf("build genl message header failed.\n");
        ret = -1;
        goto error_free;
    }

    NLA_PUT_U32(msg, TCMU_ATTR_DEVICE_ID, dev_id);
    NLA_PUT_S32(msg, TCMU_ATTR_CMD_STATUS, status);

    ret = nl_send_auto(handler->sock, msg);

error_free:
    nlmsg_free(msg);
    return ret;
nla_put_failure:
    /* NLA_PUT* macros jump here in case of an error */
    nlmsg_free(msg);
    return -1;
}
static int tcmu_parse_genl_msg(struct nl_cache_ops *cache_ops, struct genl_cmd *cmd,
                        struct genl_info *info, void *arg)
{
    struct libtcmu2_handler *handler = arg;
    u32 dev_udev_minor = nla_get_u32(info->attrs[TCMU_ATTR_MINOR]);
    u32 dev_id = nla_get_u32(info->attrs[TCMU_ATTR_DEVICE_ID]);
    int ret, reply;

    switch (cmd->c_id) {
    case TCMU_CMD_ADDED_DEVICE:
        ret = add_device(dev_udev_minor, handler);
        reply = TCMU_CMD_ADDED_DEVICE_DONE;
        break;
    case TCMU_CMD_REMOVED_DEVICE:
        ret = remove_device(dev_udev_minor, handler);
        reply = TCMU_CMD_REMOVED_DEVICE_DONE;
        break;
    default:
        printf("Unsupported command %d.\n", cmd->c_id);
        return -1;
    }

    return netlink_reply(dev_id, reply, handler, ret);
}

/* TODO: still unsupport async command process
   kernel_src/Documentation/taget/tcmu-design.txt */
void libtcmu2_process_dev_ringbuffer(struct tcmu_device *tdev)
{
    struct tcmu_mailbox *mb = tdev->map;
    struct tcmu_cmd_entry *ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;
    int did_some_work = 0;

    /* Process events from cmd ring until we catch up with cmd_head */
    while(ent != (void *)mb + mb->cmdr_off + mb->cmd_head) {
        if(tcmu_hdr_get_op(ent->hdr.len_op) == TCMU_OP_CMD) {
            uint8_t *cdb = (void *)mb + ent->req.cdb_off;
            bool success = true;
            uint8_t sense[TCMU_SENSE_BUFFERSIZE];

            /* Handle command here. */
            printf("SCSI opcode: 0x%x\n", cdb[0]);
            success = tdev->handler->handle_scsi(tdev, cdb, ent->req.iov, ent->req.iov_cnt, &sense);

            /* Set response fields */
            if(success)
                ent->rsp.scsi_status = SCSI_NO_SENSE;
            else {
                /* Also fill in rsp->sense_buffer here */
                ent->rsp.scsi_status = SCSI_CHECK_CONDITION;
                memcpy(ent->rsp.sense_buffer, sense, TCMU_SENSE_BUFFERSIZE);
            }
        } else if(tcmu_hdr_get_op(ent->hdr.len_op) != TCMU_OP_PAD) {
            /* Tell the kernel we didn't handle unknown opcodes */
            ent->hdr.uflags |= TCMU_UFLAG_UNKNOWN_OP;
        } else {
            /* Do nothing for PAD entries except update cmd_tail */
        }

        /* update cmd_tail */
        mb->cmd_tail = (mb->cmd_tail + tcmu_hdr_get_len(&ent->hdr)) % mb->cmdr_size;
        ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;
        did_some_work = 1;
    }

    /* Notify the kernel that work has been finished */
    if(did_some_work) {
        uint32_t buf = 0;

        write(tdev->fd, &buf, 4);
    }
}
