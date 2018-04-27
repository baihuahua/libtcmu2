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

#ifndef __LIBTCMU2_H
#define __LIBTCMU2_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>

#define TCMU_DEVICE_HBA_SIZE 8
#define TCMU_DEVICE_NAME_SIZE 128
#define TCMU_DEVICE_CFGSTR_SIZE 128

struct tcmu_device;

struct libtcmu2_handler {
    const char *subtype;

    bool (*check_config)(const char *cfgstr);
    bool (*open_device)(const char *cfgstr);
    bool (*close_device)(const char *name);
};

struct tcmu_device {
    char name[TCMU_DEVICE_NAME_SIZE];
    char hba_index[TCMU_DEVICE_HBA_SIZE];
    char cfgstr[TCMU_DEVICE_CFGSTR_SIZE];

    int fd;
    struct tcmu_mailbox *mmap;
    size_t mmap_size;

    uint32_t cmd_tail;

    struct libtcmu2_handler *handler;

    void *private; /* used by daemon */
};

#define TCMU_ASYNC_HANDLED -1
#define SENSE_BUFFERSIZE 96

struct scsi_cmd {
    uint16_t cmd_id;
    uint8_t *cdb;
    struct iovec *iovec;
    size_t iov_cnt;
    uint8_t sense[SENSE_BUFFERSIZE];
    int result;
};

void libtcmu2_close_device(struct tcmu_device *tdev);
struct tcmu_device *libtcmu2_open_device(const char *cfgstr);
void libtcmu2_register_handler(struct libtcmu2_handler *handler);
int libtcmu2_get_cdb_length(uint8_t *cdb);
uint64_t libtcmu2_get_lba(uint8_t *cdb);
struct scsi_cmd *libtcmu2_get_scsi_command(struct tcmu_device *tdev);
void libtcmu2_complete_scsi_command(struct tcmu_device *tdev, struct scsi_cmd *cmd);
void libtcmu2_process_scsi_prepare(struct tcmu_device *tdev);
void libtcmu2_process_scsi_done(struct tcmu_device *tdev);

/* SCSI part */
#define ASC_INVALID_FIELD_IN_CDB 0x2400
#define ASC_INVALID_OPCODE_IN_CDB 0x2000

int libtcmu2_set_sense(uint8_t *sense, uint8_t key, uint16_t asc_ascq);
int libtcmu2_emulate_inquiry(uint8_t *cdb, struct iovec *iovec,
                              uint32_t iov_cnt, uint8_t *sense);
int libtcmu2_emulate_test_unit_ready(uint8_t *cdb, struct iovec *vec,
                                     uint32_t vec_cnt, uint8_t *sense);
int libtcmu2_emulate_read_capacity_16(uint64_t num_lbas, uint32_t block_size,
                                      uint8_t *cdb, struct iovec *iovec,
                                      size_t iov_cnt, uint8_t *sense);
#endif
