/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017  Jarrod and Daniel Moura
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

/* Includes */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/l2cap.h"
#include "lib/uuid.h"
#include "lib/mgmt.h"

#include "src/shared/io.h"
#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/timeout.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/mgmt.h"
#include "src/shared/ad.h"
#include "profiles/midi/libmidi.h"

/* Defines */
#define UUID_GAP					0x1800
#define UUID_GATT					0x1801
#define ATT_CID 4

/*!
 * The following struct is used to track the gatt
 * server properties
 */
struct server {
	int fd;							/* File pointer for connection    */
	struct bt_att *att;				/* Attributes                     */
	struct gatt_db *db;				/* Database                       */
	struct bt_gatt_server *gatt;	/* The server                     */
	uint16_t gatt_svc_chngd_handle;	/* Handle for change notice       */
	bool svc_chngd_enabled;		    /* Enable flag for service change */

	/* MIDI Service Handlers */
	struct io *io;
	struct gatt_db_attribute *midi_io;
	uint16_t midi_io_handle;
	bool midi_notice_enabled;

	/* ALSA handlers */
	snd_seq_t *seq_handle;
	int seq_client_id;
	int seq_port_id;

	/* MIDI parser*/
	struct midi_read_parser midi_in;
	struct midi_write_parser midi_out;
};

/* Local Variables */
static const char *gattName = "BLE-MIDI Device";
static bool runServer = true;
static bool verbose = false;

/* Functions */
static void signal_cb(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		if (runServer) {
			mainloop_quit();
			runServer = false;
		} else {
			exit(0);
		}
		break;
	default:
		break;
	}
}

static void att_disconnect_cb(int err, void *user_data)
{
	struct server *server = (struct server *)user_data;

	midi_read_free(&server->midi_in);
	midi_write_free(&server->midi_out);
	if (server->io) {
		io_destroy(server->io);
	}
	if (server->seq_port_id >= 0) {
		snd_seq_delete_simple_port(server->seq_handle, server->seq_port_id);
		server->seq_port_id = -1;
	}
	if (server->seq_handle) {
		snd_seq_close(server->seq_handle);
		server->seq_handle = NULL;
	}

	mainloop_quit();
	if (verbose) {
		printf("Device disconnected: %s\n", strerror(err));
	}
}

static void att_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;
	printf("%s%s\n", prefix, str);
}

static void gatt_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;
	printf("%s%s\n", prefix, str);
}

static void gap_device_name_read_cb(struct gatt_db_attribute *attrib, unsigned int id, uint16_t offset, uint8_t opcode, struct bt_att *att, void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;
	size_t len = 0;
	const uint8_t *value = NULL;

	len = strlen(gattName);

	if (offset > len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
	} else {
		len -= offset;
		value = len ? &gattName[offset] : NULL;
	}

	gatt_db_attribute_read_result(attrib, id, error, value, len);
}

static void gap_device_name_ext_prop_read_cb(struct gatt_db_attribute *attrib, unsigned int id, uint16_t offset, uint8_t opcode, struct bt_att *att, void *user_data)
{
	uint8_t value[2];

	value[0] = BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE;
	value[1] = 0;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void gatt_service_changed_cb(struct gatt_db_attribute *attrib, unsigned int id, uint16_t offset, uint8_t opcode, struct bt_att *att, void *user_data)
{
	gatt_db_attribute_read_result(attrib, id, 0, NULL, 0);
}

static void gatt_svc_chngd_ccc_read_cb(struct gatt_db_attribute *attrib, unsigned int id, uint16_t offset, uint8_t opcode, struct bt_att *att, void *user_data)
{
	struct server *server = user_data;
	uint8_t value[2];

	value[0] = server->svc_chngd_enabled ? 0x02 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void gatt_svc_chngd_ccc_write_cb(struct gatt_db_attribute *attrib, unsigned int id, uint16_t offset, const uint8_t *value, size_t len, uint8_t opcode, struct bt_att *att, void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
	}else if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
	} else if (value[0] == 0x00) {
		server->svc_chngd_enabled = false;
	} else if (value[0] == 0x02) {
		server->svc_chngd_enabled = true;
	} else {
		ecode = 0x80;
	}

	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void confirm_write(struct gatt_db_attribute *attr, int err, void *user_data) {
	if (err && verbose) {
		printf("Error caching attribute %p - err: %d\n", attr, err);
	}
}

static void midi_ccc_write_cb(struct gatt_db_attribute *attrib, unsigned int id, uint16_t offset, const uint8_t *value, size_t len, uint8_t opcode, struct bt_att *att, void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
	} else if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
	} else if (value[0] == 0x00) {
		server->midi_notice_enabled = false;
	} else if (value[0] == 0x01) {
		server->midi_notice_enabled = true;
	} else {
		ecode = 0x80;
	}

	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void midi_ccc_read_cb(struct gatt_db_attribute *attrib, unsigned int id, uint16_t offset, uint8_t opcode, struct bt_att *att, void *user_data)
{
	struct server *server = user_data;
	uint8_t value[2];

	value[0] = server->midi_notice_enabled ? 0x01 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, 2);
}

static bool midi_notify_cb(struct io *io, void *user_data)
{
	struct server *server = user_data;
	int err;

	void foreach_cb(const struct midi_write_parser *parser, void *user_data) {
		struct server *server = user_data;
		if (server->midi_notice_enabled) {
			bt_gatt_server_send_notification(server->gatt, server->midi_io_handle, midi_write_data(parser), midi_write_data_size(parser));
		}
	};

	do {
		snd_seq_event_t *event = NULL;

		err = snd_seq_event_input(server->seq_handle, &event);
		if (err < 0 || !event) {
			break;
		}

		midi_read_ev(&server->midi_out, event, foreach_cb, server);
	} while (err > 0);

	if (midi_write_has_data(&server->midi_out)) {
		if (server->midi_notice_enabled) {
			bt_gatt_server_send_notification(server->gatt, server->midi_io_handle, (void *)midi_write_data(&server->midi_out), midi_write_data_size(&server->midi_out));
		}
	}

	midi_write_reset(&server->midi_out);

	return true;
}

static void midi_write_cb(struct gatt_db_attribute *attrib, unsigned int id, uint16_t offset, const uint8_t *value, size_t len, uint8_t opcode, struct bt_att *att, void *user_data)
{
	struct server *server = (struct server *)user_data;
	snd_seq_event_t ev;
	unsigned int i = 0;
	uint8_t ecode = 0;

	if (len < 3) {
		fprintf(stderr, "MIDI I/O: Wrong packet format: length is %u bytes but it should be at least 3 bytes\n", (unsigned int) len);
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
	} else {
		snd_seq_ev_clear(&ev);
		snd_seq_ev_set_source(&ev, server->seq_port_id);
		snd_seq_ev_set_subs(&ev);
		snd_seq_ev_set_direct(&ev);

		midi_read_reset(&server->midi_in);

		while (i < len) {
			size_t count = midi_read_raw(&server->midi_in, value + i, len - i, &ev);

			if (count == 0) {
				fprintf(stderr, "Wrong BLE-MIDI message\n");
				ecode = BT_ATT_ERROR_UNLIKELY;
				break;
			}

			if (ev.type != SND_SEQ_EVENT_NONE) {
				snd_seq_event_output_direct(server->seq_handle, &ev);
			}

			i += count;
		}
	}

	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void populate_gap_service(struct server *server) {
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *tmp;
	uint16_t appearance;

	/* Add the GAP service */
	bt_uuid16_create(&uuid, UUID_GAP);
	service = gatt_db_add_service(server->db, &uuid, true, 6);

	/*
	 * Device Name characteristic. Make the value dynamically read and
	 * written via callbacks.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	gatt_db_service_add_characteristic(service, &uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_EXT_PROP,
					gap_device_name_read_cb,
					NULL,
					server);

	bt_uuid16_create(&uuid, GATT_CHARAC_EXT_PROPER_UUID);
	gatt_db_service_add_descriptor(service, &uuid, BT_ATT_PERM_READ,
					gap_device_name_ext_prop_read_cb, NULL, server);

	/*
	 * Appearance characteristic. Reads and writes should obtain the value
	 * from the database.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	tmp = gatt_db_service_add_characteristic(service, &uuid,
							BT_ATT_PERM_READ,
							BT_GATT_CHRC_PROP_READ,
							NULL, NULL, server);

	/*
	 * Write the appearance value to the database, since we're not using a
	 * callback.
	 */
	put_le16(128, &appearance);
	gatt_db_attribute_write(tmp, 0, (void *) &appearance,
							sizeof(appearance),
							BT_ATT_OP_WRITE_REQ,
							NULL, confirm_write,
							NULL);
	gatt_db_service_set_active(service, true);
}

static void populate_gatt_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *svc_chngd;

	/* Add the GATT service */
	bt_uuid16_create(&uuid, UUID_GATT);
	service = gatt_db_add_service(server->db, &uuid, true, 4);

	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	svc_chngd = gatt_db_service_add_characteristic(service, &uuid,
			BT_ATT_PERM_READ,
			BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_INDICATE,
			gatt_service_changed_cb,
			NULL, server);
	server->gatt_svc_chngd_handle = gatt_db_attribute_get_handle(svc_chngd);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
				BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
				gatt_svc_chngd_ccc_read_cb,
				gatt_svc_chngd_ccc_write_cb, server);
	gatt_db_service_set_active(service, true);
}

static int populate_midi_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service;
	struct pollfd pfd;
	int err;
	snd_seq_client_info_t *info;

	/* ALSA Sequencer Client and Port Setup */
	err = snd_seq_open(&server->seq_handle, "default", SND_SEQ_OPEN_DUPLEX, 0);
	if (err < 0) {
		fprintf(stderr, "Could not open ALSA Sequencer: %s (%d)\n", snd_strerror(err), err);
		return 1;
	}

	err = snd_seq_nonblock(server->seq_handle, SND_SEQ_NONBLOCK);
	if (err < 0) {
		fprintf(stderr, "Could not set nonblock mode: %s (%d)\n", snd_strerror(err), err);
		goto _err_handle;
	}

	err = snd_seq_set_client_name(server->seq_handle, gattName);
	if (err < 0) {
		fprintf(stderr, "Could not configure ALSA client: %s (%d)\n", snd_strerror(err), err);
		goto _err_handle;
	}

	err = snd_seq_client_id(server->seq_handle);
	if (err < 0) {
		fprintf(stderr, "Could not retrieve ALSA client: %s (%d)\n", snd_strerror(err), err);
		goto _err_handle;
	}
	server->seq_client_id = err;

	err = snd_seq_create_simple_port(server->seq_handle, gattName,
									 SND_SEQ_PORT_CAP_READ |
									 SND_SEQ_PORT_CAP_WRITE |
									 SND_SEQ_PORT_CAP_SUBS_READ |
									 SND_SEQ_PORT_CAP_SUBS_WRITE,
									 SND_SEQ_PORT_TYPE_MIDI_GENERIC |
									 SND_SEQ_PORT_TYPE_HARDWARE);
	if (err < 0) {
		fprintf(stderr, "Could not create ALSA port: %s (%d)\n", snd_strerror(err), err);
		goto _err_handle;
	}
	server->seq_port_id = err;

	snd_seq_client_info_alloca(&info);
	err = snd_seq_get_client_info(server->seq_handle, info);
	if (err < 0) {
		fprintf(stderr, "Could not get client info: %s (%d)\n", snd_strerror(err), err);
		goto _err_port;
	}

	/* list of relevant sequencer events */
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_NOTEOFF);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_NOTEON);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_KEYPRESS);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_CONTROLLER);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_PGMCHANGE);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_CHANPRESS);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_PITCHBEND);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_SYSEX);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_QFRAME);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_SONGPOS);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_SONGSEL);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_TUNE_REQUEST);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_CLOCK);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_START);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_CONTINUE);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_STOP);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_SENSING);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_RESET);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_CONTROL14);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_NONREGPARAM);
	snd_seq_client_info_event_filter_add(info, SND_SEQ_EVENT_REGPARAM);

	err = snd_seq_set_client_info(server->seq_handle, info);
	if (err < 0) {
		fprintf(stderr, "Could not set client info: %s (%d)\n", snd_strerror(err), err);
		goto _err_port;
	}
	
	/* Input file descriptors */
	snd_seq_poll_descriptors(server->seq_handle, &pfd, 1, POLLIN);

	server->io = io_new(pfd.fd);
	if (!server->io) {
		fprintf(stderr, "Could not allocate I/O eventloop\n");
		goto _err_port;
	}

	io_set_read_handler(server->io, midi_notify_cb, server, NULL);

	/* Init the MIDI parser */
	err = midi_read_init(&server->midi_in);
	if (err < 0) {
		fprintf(stderr, "Could not initialise MIDI input parser\n");
		goto _err_port;
	}

	err = midi_write_init(&server->midi_out, bt_att_get_mtu(server->att) - 3);
	if (err < 0) {
		fprintf(stderr, "Could not initialise MIDI output parser\n");
		goto _err_midi;
	}

	/* Add MIDI Service */
	bt_string_to_uuid(&uuid, MIDI_UUID);
	service = gatt_db_add_service(server->db, &uuid, true, 6);

	/* Add MIDI IO Characteristics */
	bt_string_to_uuid(&uuid, MIDI_IO_UUID);
	server->midi_io = gatt_db_service_add_characteristic(service, &uuid,
						BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP | BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
						NULL, midi_write_cb, server);
	server->midi_io_handle = gatt_db_attribute_get_handle(server->midi_io);

	/* Add MIDI CCC */
	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					midi_ccc_read_cb, midi_ccc_write_cb, server);

	/* Activate Service */
	gatt_db_service_set_active(service, true);

	return 0;

_err_midi:
	midi_read_free(&server->midi_in);

_err_port:
	snd_seq_delete_simple_port(server->seq_handle, server->seq_port_id);

_err_handle:
	snd_seq_close(server->seq_handle);
	server->seq_handle = NULL;

	return -1;
}

static void add_adv_callback(uint8_t status, uint16_t length,
							const void *param, void *user_data)
{
// 	struct btd_adv_client *client = user_data;
	const struct mgmt_rp_add_advertising *rp = param;

	if (status)
		goto done;

	if (!param || length < sizeof(*rp)) {
		status = MGMT_STATUS_FAILED;
		goto done;
	}
done:
	printf("Blz\n");
}

static int advertise(int dev_id)
{
	struct mgmt *mgmt_if = NULL;
	struct bt_ad *data;
	uint8_t *adv_data;
	size_t adv_data_len;
	struct mgmt_cp_add_advertising *cp;
	uint8_t param_len;
	bt_uuid_t uuid;
	
	bt_string_to_uuid(&uuid, MIDI_UUID);

	mgmt_if = mgmt_new_default();
	if (!mgmt_if) {
		fprintf(stderr, "Failed to access management interface\n");
		return -1;
	}

	data = bt_ad_new();
	if (!data) {
		fprintf(stderr, "Error creating adverting data\n");
		return -1;
	}

	if (!bt_ad_add_service_uuid(data, &uuid)) {
		fprintf(stderr, "Error adding service UUID\n");
		return -1;
	}

	adv_data = bt_ad_generate(data, &adv_data_len);
	if (!adv_data) {
		fprintf(stderr, "Error generating advertising data\n");
		return -1;
	}

	param_len = sizeof(struct mgmt_cp_add_advertising) + adv_data_len;
	cp = malloc0(param_len);
	if (!cp) {
		fprintf(stderr, "Error allocating memory to advertising params\n");
		return -1;
	}

	cp->flags = htobl(MGMT_ADV_FLAG_CONNECTABLE | MGMT_ADV_FLAG_DISCOV);
	cp->instance = 0;
	cp->adv_data_len = adv_data_len;
	memcpy(cp->data, adv_data, adv_data_len);

	free(adv_data);

	if (!mgmt_send(mgmt_if, MGMT_OP_ADD_ADVERTISING, dev_id, param_len,
				cp, add_adv_callback, NULL, NULL)) {
		fprintf(stderr, "Failed to add Advertising Data");
		free(cp);
		return -1;
	}

	free(cp);
	bt_ad_unref(data);
	mgmt_unref(mgmt_if);

	return 0;
}

static int l2cap_le_att_listen_and_accept(bdaddr_t *src, int sec,
							uint8_t src_type)
{
	int sk, nsk;
	struct sockaddr_l2 srcaddr, addr;
	socklen_t optlen;
	struct bt_security btsec;
	char ba[18];
	int dev_id;
	
	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Failed to create L2CAP socket");
		return -1;
	}

	dev_id = hci_get_route(src);
	if (dev_id < 0) {
		errno = ENODEV;
		fprintf(stderr, "Device ID not found\n");
		goto fail;
	}

	if (advertise(dev_id) != 0) {
		goto fail;
	}

	/* Set up source address */
	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.l2_family = AF_BLUETOOTH;
	srcaddr.l2_cid = htobs(ATT_CID);
	srcaddr.l2_bdaddr_type = src_type;
	bacpy(&srcaddr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0) {
		perror("Failed to bind L2CAP socket");
		goto fail;
	}

	/* Set the security level */
	memset(&btsec, 0, sizeof(btsec));
	btsec.level = sec;
	if (setsockopt(sk, SOL_BLUETOOTH, BT_SECURITY, &btsec,
							sizeof(btsec)) != 0) {
		fprintf(stderr, "Failed to set L2CAP security level\n");
		goto fail;
	}

	if (listen(sk, 10) < 0) {
		perror("Listening on socket failed");
		goto fail;
	}

	if (verbose) {
		printf("Started listening on ATT channel. Waiting for connections\n");
	}

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);
	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
	if (nsk < 0) {
		perror("Accept failed");
		goto fail;
	}

	if (verbose) {
		ba2str(&addr.l2_bdaddr, ba);
		printf("Connect from %s\n", ba);
	}
	
	close(sk);

	return nsk;

fail:
	close(sk);
	return -1;
}

static struct server *server_create(int fd, uint16_t mtu)
{
	struct server *server;
	size_t name_len = strlen(gattName);
	int err;

	server = new0(struct server, 1);
	if (!server) {
		fprintf(stderr, "Failed to allocate memory for server\n");
		return NULL;
	}

	/* Init values */
	server->io = NULL;
	server->seq_port_id = -1;
	server->seq_handle = NULL;

	server->att = bt_att_new(fd, false);
	if (!server->att) {
		fprintf(stderr, "Failed to initialze ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_set_close_on_unref(server->att, true)) {
		fprintf(stderr, "Failed to set up ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_register_disconnect(server->att, att_disconnect_cb, server, NULL)) {
		fprintf(stderr, "Failed to set ATT disconnect handler\n");
		goto fail;
	}

	server->fd = fd;
	server->db = gatt_db_new();
	if (!server->db) {
		fprintf(stderr, "Failed to create GATT database\n");
		goto fail;
	}

	server->gatt = bt_gatt_server_new(server->db, server->att, mtu);
	if (!server->gatt) {
		fprintf(stderr, "Failed to create GATT server\n");
		goto fail;
	}

	if (verbose) {
		bt_att_set_debug(server->att, att_debug_cb, "att: ", NULL);
		bt_gatt_server_set_debug(server->gatt, gatt_debug_cb, "server: ", NULL);
	}

	/* Populate our databases */
	populate_gap_service(server);
	populate_gatt_service(server);
	err = populate_midi_service(server);
	if (err < 0) {
		fprintf(stderr, "Failed to populate midi service\n");
		goto fail;
	}

	return server;

fail:
	gatt_db_unref(server->db);
	bt_att_unref(server->att);
	free(server);

	return NULL;
}

static void server_destroy(struct server *server)
{
	bt_gatt_server_unref(server->gatt);
	gatt_db_unref(server->db);
}

static void usage(void)
{
	printf("btmidi-server\n");
	printf("Usage:\n\tbtmidi-server [options]\n");

	printf("Options:\n"
		"\t-i, --index <id>\t\tSpecify adapter index, e.g. hci0\n"
		"\t-m, --mtu <mtu>\t\t\tThe ATT MTU to use\n"
		"\t-s, --security-level <sec>\tSet security level (low|"
								"medium|high)\n"
		"\t-t, --type [random|public] \t The source address type\n"
		"\t-v, --verbose\t\t\tEnable extra logging\n"
		"\t-n, --name\t\t\tSet the BLE device name\n"
		"\t-h, --help\t\t\tDisplay help\n");
}

static struct option main_options[] = {
	{ "index",		1, 0, 'i' },
	{ "mtu",		1, 0, 'm' },
	{ "security-level",	1, 0, 's' },
	{ "type",		1, 0, 't' },
	{ "verbose",		0, 0, 'v' },
	{ "name",		0, 0, 'n' },
	{ "help",		0, 0, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	int opt;
	bdaddr_t src_addr;
	int dev_id = -1;
	int fd;
	int sec = BT_SECURITY_LOW;
	uint8_t src_type = BDADDR_LE_PUBLIC;
	uint16_t mtu = 0;
	sigset_t mask;
	struct server *server;

	while ((opt = getopt_long(argc, argv, "+hvrs:t:m:i:",
						main_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return EXIT_SUCCESS;
		case 'v':
			verbose = true;
			break;
		case 's':
			if (strcmp(optarg, "low") == 0)
				sec = BT_SECURITY_LOW;
			else if (strcmp(optarg, "medium") == 0)
				sec = BT_SECURITY_MEDIUM;
			else if (strcmp(optarg, "high") == 0)
				sec = BT_SECURITY_HIGH;
			else {
				fprintf(stderr, "Invalid security level\n");
				return EXIT_FAILURE;
			}
			break;
		case 't':
			if (strcmp(optarg, "random") == 0)
				src_type = BDADDR_LE_RANDOM;
			else if (strcmp(optarg, "public") == 0)
				src_type = BDADDR_LE_PUBLIC;
			else {
				fprintf(stderr,
					"Allowed types: random, public\n");
				return EXIT_FAILURE;
			}
			break;
		case 'm': {
			int arg;

			arg = atoi(optarg);
			if (arg <= 0) {
				fprintf(stderr, "Invalid MTU: %d\n", arg);
				return EXIT_FAILURE;
			}

			if (arg > UINT16_MAX) {
				fprintf(stderr, "MTU too large: %d\n", arg);
				return EXIT_FAILURE;
			}

			mtu = (uint16_t) arg;
			break;
		}
		case 'i':
			dev_id = hci_devid(optarg);
			if (dev_id < 0) {
				perror("Invalid adapter");
				return EXIT_FAILURE;
			}

			break;
		case 'n':
			if (strlen(optarg) > 0) {
				gattName = optarg;
			} else {
				perror("Missing name value");
			}
			break;
		default:
			fprintf(stderr, "Invalid option: %c\n", opt);
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv -= optind;
	optind = 0;

	if (argc) {
		usage();
		return EXIT_SUCCESS;
	}

	if (dev_id == -1)
		bacpy(&src_addr, BDADDR_ANY);
	else if (hci_devba(dev_id, &src_addr) < 0) {
		perror("Adapter not available");
		return EXIT_FAILURE;
	}

	while (runServer) {
		int client;
		int port;
		
		runServer = false;
		
		mainloop_init();

		fd = l2cap_le_att_listen_and_accept(&src_addr, sec, src_type);
		if (fd < 0) {
			fprintf(stderr, "Failed to accept L2CAP ATT connection\n");
			return EXIT_FAILURE;
		}

		server = server_create(fd, mtu);
		if (!server) {
			close(fd);
			return EXIT_FAILURE;
		}

		runServer = true;
		sigemptyset(&mask);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGTERM);

		mainloop_set_signal(&mask, signal_cb, NULL, NULL);

		mainloop_run();

		server_destroy(server);
	}

	return EXIT_SUCCESS;
}
