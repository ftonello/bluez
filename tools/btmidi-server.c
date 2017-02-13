/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017  Felipe F. Tonello <eu@felipetonello.com>
 *    with great help from Daniel Moura <oxe@oxesoft.com>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>

#include "lib/bluetooth.h"
#include "lib/l2cap.h"
#include "lib/uuid.h"
#include "lib/mgmt.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"

#include "src/shared/io.h"
#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/mgmt.h"
#include "src/shared/ad.h"

#include "profiles/midi/libmidi.h"

/* Attribute Protocol Channel Identifier */
#define ATT_CID 4

struct midi_server {
	bdaddr_t src_addr;
	uint8_t src_addr_type;
	bdaddr_t dst_addr;
	uint8_t dst_addr_type;
	struct mgmt *mgmt;
	struct bt_att *att;
	struct gatt_db *db;
	struct bt_gatt_server *gatt;

	/* MIDI Service Handlers */
	struct io *io;
	uint16_t midi_io_handle;
	bool midi_notify_enabled;

	/* ALSA handlers */
	snd_seq_t *seq_handle;
	int seq_client_id;
	int seq_port_id;

	/* MIDI parser*/
	struct midi_read_parser midi_in;
	struct midi_write_parser midi_out;
};

/* from src/adapter.h */
#define MAX_NAME_LENGTH 248

static struct btmidi_options {
	char peripheral_name[MAX_NAME_LENGTH];
	bool verbose;
	int index;
} options = {
	.peripheral_name = "BlueZ MIDI",
	.verbose = false,
	.index = 0,
};

static void signal_cb(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	default:
		break;
	}
}

static void mgmt_generic_cb(uint8_t status, uint16_t length,
                            const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		fprintf(stderr, "%s failed: %s\n",
		(char*)user_data, mgmt_errstr(status));
		return;
	}

	if (options.verbose)
		printf("%s completed\n", (char*)user_data);
}

static void adapter_removed_cb(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	if (options.verbose) {
		printf("%s\n", (char*)user_data);
	}
}

static uint8_t* ad_generate_data(size_t *adv_data_len)
{
	uint8_t *adv_data;
	struct bt_ad *data;
	bt_uuid_t uuid;

	data = bt_ad_new();
	if (!data) {
		fprintf(stderr, "Error creating adverting data\n");
		return NULL;
	}

	bt_string_to_uuid(&uuid, MIDI_UUID);
	if (!bt_ad_add_service_uuid(data, &uuid)) {
		fprintf(stderr, "Error adding service UUID\n");
		goto _error;
	}

	adv_data = bt_ad_generate(data, adv_data_len);
	if (!adv_data) {
		fprintf(stderr, "Error generating advertising data\n");
		goto _error;
	}

	/* TODO: Slave Preferred Connection Interval */

	bt_ad_unref(data);

	return adv_data;

_error:
	bt_ad_unref(data);
	return NULL;
}

static int advertise(struct midi_server *midi)
{
	int err = 0;
	uint8_t *adv_data;
	size_t adv_data_len;
	/* struct mgmt_cp_load_conn_param *load_conn_params; */
	/* struct mgmt_conn_param conn_param; */
	/* struct mgmt_cp_set_local_name *localname; */
	struct mgmt_cp_add_advertising *add_adv;
	/* uint8_t load_conn_params_len; */
	uint8_t add_adv_len;
	uint32_t flags;
	uint8_t val;

	adv_data = ad_generate_data(&adv_data_len);
	if (!adv_data)
		return -1;

	/* val = 0x00; */
	/* if (!mgmt_send(midi->mgmt, MGMT_OP_SET_POWERED, options.index, 1, */
	/* 		&val, mgmt_generic_callback_complete, "MGMT_OP_SET_POWERED", */
	/* 		NULL)) { */
	/* 	fprintf(stderr, "Failed setting powered off\n"); */
	/* 	goto _free_adv_data; */
	/* } */

	/* FIXME: This should be updated once device is connected */
	/* load_conn_params_len = sizeof(*load_conn_params) + sizeof(conn_param); */
	/* load_conn_params = alloca(load_conn_params_len); */

	/* bacpy(&conn_param.addr.bdaddr, &midi->dst_addr); */
	/* conn_param.addr.type = midi->dst_addr_type; */
	/* conn_param.min_interval = 6; */
	/* conn_param.max_interval = 12; */
	/* conn_param.latency = 0; */
	/* conn_param.timeout = 200; */
	/* load_conn_params->param_count = 1; */

	/* memcpy(load_conn_params->params, &conn_param, sizeof(conn_param)); */

	/* if (mgmt_send(midi->mgmt, MGMT_OP_LOAD_CONN_PARAM, */
	/* 		options.index, load_conn_params_len, load_conn_params, */
	/* 		mgmt_generic_cb, "MGMT_OP_LOAD_CONN_PARAM", */
	/* 		NULL) == 0) { */
	/* 	fprintf(stderr, "Failed to load connection parameters\n"); */
	/* 	goto _free_load_conn_params; */
	/* } */

	/* localname = malloc0(sizeof(struct mgmt_cp_set_local_name)); */
	/* if (!localname) { */
	/* 	fprintf(stderr, "Error allocating memory to local name\n"); */
	/* 	goto _free_load_conn_params; */
	/* } */

	/* strncpy((char *)localname->name, options.peripheral_name, MGMT_MAX_NAME_LENGTH); */
	/* strncpy((char *)localname->short_name, options.peripheral_name, */
	/* 		MGMT_MAX_SHORT_NAME_LENGTH); */
	/* if (!mgmt_send(midi->mgmt, MGMT_OP_SET_LOCAL_NAME, options.index, */
	/* 		sizeof(struct mgmt_cp_set_local_name), localname, */
	/* 		mgmt_generic_callback_complete, "MGMT_OP_SET_LOCAL_NAME", */
	/* 		NULL)) { */
	/* 	fprintf(stderr, "Failed setting local name\n"); */
	/* 	goto _free_local_name; */
	/* } */


	add_adv_len = sizeof(struct mgmt_cp_add_advertising) + adv_data_len;
	add_adv = alloca(add_adv_len);

	flags = MGMT_ADV_FLAG_CONNECTABLE | MGMT_ADV_FLAG_DISCOV;
	add_adv->instance = 1;
	add_adv->flags = htobl(flags);
	add_adv->duration = 0;
	add_adv->timeout = 0;
	add_adv->adv_data_len = adv_data_len;
	add_adv->scan_rsp_len = 0;
	memcpy(add_adv->data, adv_data, adv_data_len);

	if (!mgmt_send(midi->mgmt, MGMT_OP_ADD_ADVERTISING,
			options.index, add_adv_len, add_adv,
			mgmt_generic_cb, "MGMT_OP_ADD_ADVERTISING",
			NULL)) {
		fprintf(stderr, "Failed to add advertising\n");
		err = -1;
	}

	/* val = 0x01; */
	/* if (!mgmt_send(midi->mgmt, MGMT_OP_SET_POWERED, options.index, 1, */
	/* 	&val, mgmt_generic_cb, "MGMT_OP_SET_POWERED", */
	/* 	NULL)) { */
	/* 	fprintf(stderr, "Failed setting powered on\n"); */
	/* 	goto _free_add_adv; */
	/* } */

	free(adv_data);

	return err;
}

static void att_disconnect_cb(int err, void *user_data)
{
	struct midi_server *midi = user_data;

	midi_read_free(&midi->midi_in);
	midi_write_free(&midi->midi_out);

	io_destroy(midi->io);
	midi->io = NULL;

	if (midi->seq_handle && midi->seq_port_id >= 0) {
		snd_seq_delete_simple_port(midi->seq_handle, midi->seq_port_id);
		midi->seq_port_id = -1;
	}

	if (midi->seq_handle) {
		snd_seq_close(midi->seq_handle);
		midi->seq_handle = NULL;
	}

	bt_gatt_server_unref(midi->gatt);
	bt_att_unref(midi->att);

	if (options.verbose)
		printf("Device disconnected: %s\n", strerror(err));

	err = advertise(midi);
	if (err < 0) {
		fprintf(stderr, "Coudln't setup advertisement");
		mainloop_quit();
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

static void confirm_write(struct gatt_db_attribute *attr, int err,
                          void *user_data)
{
	if (!err)
		return;

	fprintf(stderr, "Error caching attribute %p - err: %d\n", attr, err);

	/* we quit the program since something went wrong that we can't cotinue */
	mainloop_quit();
}

static void midi_ccc_write_cb(struct gatt_db_attribute *attrib,
	unsigned int id, uint16_t offset, const uint8_t *value,
	size_t len, uint8_t opcode, struct bt_att *att, void *user_data)
{
	struct midi_server *midi = user_data;
	uint8_t ecode = 0;

	if (!value || len != 2)
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
	else if (offset)
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
	else if (value[0] == 0x00)
		midi->midi_notify_enabled = false;
	else if (value[0] == 0x01)
		midi->midi_notify_enabled = true;
	else
		ecode = BT_ATT_ERROR_INVALID_PDU;

	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void midi_ccc_read_cb(struct gatt_db_attribute *attrib,
	unsigned int id, uint16_t offset, uint8_t opcode,
	struct bt_att *att, void *user_data)
{
	struct midi_server *midi = user_data;
	uint8_t value[2];

	value[0] = midi->midi_notify_enabled ? 0x01 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static bool midi_notify_cb(struct io *io, void *user_data)
{
	struct midi_server *midi = user_data;
	int err;

	void foreach_cb(const struct midi_write_parser *parser,
		void *user_data) {
		struct midi_server *midi = user_data;
		/* TODO write to att table */
		if (midi->midi_notify_enabled)
			bt_gatt_server_send_notification(midi->gatt,
				midi->midi_io_handle, midi_write_data(parser),
				midi_write_data_size(parser));
	};

	do {
		snd_seq_event_t *event = NULL;

		err = snd_seq_event_input(midi->seq_handle, &event);
		if (err < 0 || !event) {
			break;
		}

		midi_read_ev(&midi->midi_out, event, foreach_cb, midi);
	} while (err > 0);

	if (midi_write_has_data(&midi->midi_out)) {
		/* TODO write to att table */
		if (midi->midi_notify_enabled)
		bt_gatt_server_send_notification(midi->gatt,
			midi->midi_io_handle,
			(void *)midi_write_data(&midi->midi_out),
			midi_write_data_size(&midi->midi_out));
	}

	midi_write_reset(&midi->midi_out);

	return true;
}

static void midi_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{

}

static void midi_write_cb(struct gatt_db_attribute *attrib,
	unsigned int id, uint16_t offset, const uint8_t *value,
	size_t len, uint8_t opcode, struct bt_att *att, void *user_data)
{
	struct midi_server *midi = user_data;
	snd_seq_event_t ev;
	uint8_t ecode = 0;
	size_t i = 0;

	if (len < 3) {
		fprintf(stderr, "MIDI I/O: Wrong packet format: length"
			"is %lu bytes but it should be at least 3 bytes\n",
			len);
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto _err;
	}

	snd_seq_ev_clear(&ev);
	snd_seq_ev_set_source(&ev, midi->seq_port_id);
	snd_seq_ev_set_subs(&ev);
	snd_seq_ev_set_direct(&ev);

	midi_read_reset(&midi->midi_in);

	while (i < len) {
		size_t count =
			midi_read_raw(&midi->midi_in, value + i,
			              len - i, &ev);

		if (count == 0) {
			fprintf(stderr, "Wrong BLE-MIDI message\n");
			ecode = BT_ATT_ERROR_INVALID_PDU;
			break;
		}

		if (ev.type != SND_SEQ_EVENT_NONE)
			snd_seq_event_output_direct(midi->seq_handle, &ev);

		i += count;
	}

_err:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static int create_seq_port(struct midi_server *midi)
{
	int err;
	struct pollfd pfd;
	snd_seq_client_info_t *info;

	/* ALSA Sequencer Client and Port Setup */
	err = snd_seq_open(&midi->seq_handle, "default",
						SND_SEQ_OPEN_DUPLEX, 0);
	if (err < 0) {
		fprintf(
			stderr, "Could not open ALSA Sequencer: %s (%d)\n",
			snd_strerror(err), err);
		return err;
	}

	err = snd_seq_nonblock(midi->seq_handle, SND_SEQ_NONBLOCK);
	if (err < 0) {
		fprintf(stderr, "Could not set nonblock mode: %s (%d)\n",
			snd_strerror(err), err);
		goto _err_handle;
	}

	err = snd_seq_set_client_name(midi->seq_handle, options.peripheral_name);
	if (err < 0) {
		fprintf(stderr, "Could not configure ALSA client: %s (%d)\n",
			snd_strerror(err), err);
		goto _err_handle;
	}

	err = snd_seq_client_id(midi->seq_handle);
	if (err < 0) {
		fprintf(stderr, "Could not retrieve ALSA client: %s (%d)\n",
			snd_strerror(err), err);
		goto _err_handle;
	}
	midi->seq_client_id = err;

	err = snd_seq_create_simple_port(midi->seq_handle, options.peripheral_name,
									 SND_SEQ_PORT_CAP_READ |
									 SND_SEQ_PORT_CAP_WRITE |
									 SND_SEQ_PORT_CAP_SUBS_READ |
									 SND_SEQ_PORT_CAP_SUBS_WRITE,
									 SND_SEQ_PORT_TYPE_MIDI_GENERIC |
									 SND_SEQ_PORT_TYPE_HARDWARE);
	if (err < 0) {
		fprintf(stderr, "Could not create ALSA port: %s (%d)\n",
			snd_strerror(err), err);
		goto _err_handle;
	}
	midi->seq_port_id = err;

	snd_seq_client_info_alloca(&info);
	err = snd_seq_get_client_info(midi->seq_handle, info);
	if (err < 0) {
		fprintf(stderr, "Could not get client info: %s (%d)\n",
			snd_strerror(err), err);
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

	err = snd_seq_set_client_info(midi->seq_handle, info);
	if (err < 0) {
		fprintf(stderr, "Could not set client info: %s (%d)\n",
			snd_strerror(err), err);
		goto _err_port;
	}
	
	/* Input file descriptors */
	snd_seq_poll_descriptors(midi->seq_handle, &pfd, 1, POLLIN);

	midi->io = io_new(pfd.fd);
	if (!midi->io) {
		fprintf(stderr, "Could not allocate I/O eventloop\n");
		goto _err_port;
	}

	io_set_read_handler(midi->io, midi_notify_cb, midi, NULL);

	/* Init the MIDI parser */
	err = midi_read_init(&midi->midi_in);
	if (err < 0) {
		fprintf(stderr, "Could not initialise MIDI input parser\n");
		goto _err_port;
	}

	err = midi_write_init(&midi->midi_out, bt_att_get_mtu(midi->att) - 3);
	if (err < 0) {
		fprintf(stderr, "Could not initialise MIDI output parser\n");
		goto _err_midi;
	}

	return 0;

_err_midi:
	midi_read_free(&midi->midi_in);

_err_port:
	snd_seq_delete_simple_port(midi->seq_handle, midi->seq_port_id);

_err_handle:
	snd_seq_close(midi->seq_handle);
	midi->seq_handle = NULL;

	return err;
}

static void l2cap_att_cb(int fd, uint32_t events, void *user_data)
{
	int err;
	int conn_fd;
	struct sockaddr_l2 addr;
	socklen_t optlen;
	struct midi_server *midi = user_data;

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);
	conn_fd = accept(fd, (struct sockaddr *)&addr, &optlen);
	if (conn_fd < 0) {
		perror("Couldn't accept incoming connection");
		return;
	}

	if (options.verbose) {
		char ba[18];

		ba2str(&addr.l2_bdaddr, ba);
		printf("Connect to %s\n", ba);
	}

	midi->att = bt_att_new(conn_fd, false);
	if (!midi->att) {
		fprintf(stderr, "Failed to initialze ATT transport layer\n");
		goto _close_sock;
	}

	bt_att_set_security(midi->att, BT_SECURITY_LOW);

	if (!bt_att_set_close_on_unref(midi->att, true)) {
		fprintf(stderr, "Failed to set up ATT transport layer\n");
		goto _unref_att;
	}

	if (!bt_att_register_disconnect(midi->att, att_disconnect_cb,
	                                midi, NULL)) {
		fprintf(stderr, "Failed to set ATT disconnect handler\n");
		goto _unref_att;
	}

	midi->gatt = bt_gatt_server_new(midi->db, midi->att,
	                                bt_att_get_mtu(midi->att));
	if (!midi->gatt) {
		fprintf(stderr, "Failed to create GATT server\n");
		goto _unref_att;
	}

	if (options.verbose) {
		bt_att_set_debug(midi->att, att_debug_cb, "att: ", NULL);
		bt_gatt_server_set_debug(midi->gatt, gatt_debug_cb, "srv: ", NULL);
	}

	err = create_seq_port(midi);
	if (err < 0)
		goto _unref_gatt;

	return;

_unref_gatt:
	bt_gatt_server_unref(midi->gatt);
	midi->gatt = NULL;

_unref_att:
	bt_att_unref(midi->att);
	midi->att = NULL;

_close_sock:
	close(conn_fd);

	/* if connection failed somehow, continue advertising */
	err = advertise(midi);
	if (err < 0) {
		fprintf(stderr, "Coudln't setup advertisement");
		mainloop_quit();
	}
}

static int adapter_setup(struct midi_server *midi)
{
	uint8_t val;

	val = 0x01;
	if (mgmt_send(midi->mgmt, MGMT_OP_SET_LE, options.index, 1,
	              &val, mgmt_generic_cb, "MGMT_OP_SET_LE", NULL) == 0)
		return -1;

	val = 0x01;
	if (mgmt_send(midi->mgmt, MGMT_OP_SET_CONNECTABLE,
	              options.index, 1, &val, mgmt_generic_cb,
	              "MGMT_OP_SET_CONNECTABLE", NULL) == 0)
		return -1;

	/* TODO continue this */
	mgmt_register(midi->mgmt, MGMT_EV_INDEX_REMOVED,
	              options.index, adapter_removed_cb,
	              NULL, NULL);
}

static int l2cap_att_setup(bdaddr_t *src, uint8_t src_type)
{
	int att_fd, err;
	struct sockaddr_l2 addr;

	att_fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (att_fd < 0)
		return -1;

	/* Set up source address */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	addr.l2_cid = htobs(ATT_CID);
	bacpy(&addr.l2_bdaddr, src);
	addr.l2_bdaddr_type = src_type;

	err = bind(att_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0)
		goto fail;

	err = listen(att_fd, 1);
	if (err < 0)
		goto fail;

	return att_fd;

fail:
	close(att_fd);

	return -1;
}

static void populate_gap_service(struct midi_server *midi)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *tmp;
	uint16_t appearance;

	/* add the GAP service */
	bt_string_to_uuid(&uuid, GAP_UUID);
	service = gatt_db_add_service(midi->db, &uuid, true, 2);

	/* Device Name characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	tmp = gatt_db_service_add_characteristic(service, &uuid,
				BT_ATT_PERM_READ, BT_GATT_CHRC_PROP_READ,
				NULL, NULL, midi);

	/* write device name */
	gatt_db_attribute_write(tmp, 0, (uint8_t *)options.peripheral_name,
				strlen(options.peripheral_name), BT_ATT_OP_WRITE_REQ,
				NULL, confirm_write, NULL);

	/* Appearance characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	tmp = gatt_db_service_add_characteristic(service, &uuid,
				BT_ATT_PERM_READ, BT_GATT_CHRC_PROP_READ,
				NULL, NULL, midi);

	/* write appearance characteristic */
	put_le16(960, &appearance); /* Human Interface Device (HID) ? */
	gatt_db_attribute_write(tmp, 0, (uint8_t *) &appearance,
				sizeof(appearance), BT_ATT_OP_WRITE_REQ,
				NULL, confirm_write, NULL);

	/* TODO: write PPCP */

	gatt_db_service_set_active(service, true);
}

static void populate_midi_service(struct midi_server *midi)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *midi_io;

	/* add MIDI Service */
	bt_string_to_uuid(&uuid, MIDI_UUID);
	/* FIXME: 6 handles? probably 3 */
	service = gatt_db_add_service(midi->db, &uuid, true, 6);

	/* add MIDI IO Characteristic */
	bt_string_to_uuid(&uuid, MIDI_IO_UUID);
	midi_io = gatt_db_service_add_characteristic(service, &uuid,
		BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
		BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP |
		BT_GATT_CHRC_PROP_READ |
		BT_GATT_CHRC_PROP_NOTIFY,
		midi_read_cb, midi_write_cb, midi);

	midi->midi_io_handle = gatt_db_attribute_get_handle(midi_io);

	/* add MIDI CCC */
	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
		BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
		midi_ccc_read_cb, midi_ccc_write_cb, midi);

	gatt_db_service_set_active(service, true);
}

static int midi_init(struct midi_server *midi)
{
	midi->seq_port_id = -1;

	midi->mgmt = mgmt_new_default();
	if (!midi->mgmt) {
		errno = EIO;
		return -1;
	}

	midi->db = gatt_db_new();
	if (!midi->db) {
		mgmt_unref(midi->mgmt);
		errno = ENOMEM;
		return -1;
	}

	/* populate our ATT database */
	populate_gap_service(midi);
	populate_midi_service(midi);

	return 0;
}

static void midi_cleanup(struct midi_server *midi)
{
	io_destroy(midi->io);

	if (midi->seq_handle && midi->seq_port_id >= 0)
		snd_seq_delete_simple_port(midi->seq_handle, midi->seq_port_id);

	if (midi->seq_handle)
		snd_seq_close(midi->seq_handle);

	bt_gatt_server_unref(midi->gatt);
	bt_att_unref(midi->att);
	gatt_db_unref(midi->db);
	mgmt_unref(midi->mgmt);
}

static void usage()
{
	printf("Usage: btmidi-server [options]\n");
	printf("Run a BLE-MIDI GATT Server, acting as a BLE peripheral device.\n\n");

	printf("Options:\n");
	printf("    -v, --verbose   Talk a lot!\n");
	printf("    -n, --name      Set the BLE peripheral name (default: `%s')\n",
	       options.peripheral_name);
	printf("    -i, --index     Set the adapter index (default: 0)\n");
	printf("    -h, --help      Display this help and exit\n");

	/* TODO: Connection parameters options */
}

int main(int argc, char *argv[])
{
	sigset_t mask;
	int opt;
	int fd;
	int err = 0;

	static struct midi_server midi;

	static struct option main_options[] = {
		{ "verbose", no_argument      , NULL, 'v' },
		{ "name"   , required_argument, NULL, 'n' },
		{ "index"  , required_argument, NULL, 'i' },
		{ "help"   , no_argument      , NULL, 'h' },
		{ }
	};

	while ((opt = getopt_long(argc, argv, "+hvn:i:",
	                          main_options, NULL)) != -1) {
		switch (opt) {
		case 'v':
			options.verbose = true;
			break;
		case 'n':
			if (strlen(optarg) > 0)
				strncpy(options.peripheral_name, optarg,
				        sizeof(options.peripheral_name));
			else
				fprintf(stderr, "Missing name value, using default `%s' name.",
				        options.peripheral_name);
			break;
		case 'i':
			if (atoi(optarg) >= 0)
				options.index = atoi(optarg);
			else
				fprintf(stderr, "Invalid adapter, using default %d.",
				        options.index);
			break;
		case 'h':
			usage();
			return 0;
		default:
			fprintf(stderr, "Invalid option: %c\n", opt);
			usage();
			return 1;
		}
	}

	argc -= optind;
	argv -= optind;
	optind = 0;

	if (argc) {
		usage();
		return 1;
	}

	mainloop_init();

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	mainloop_set_signal(&mask, signal_cb, NULL, NULL);

	err = hci_devba(options.index, &midi.src_addr);
	if (err < 0) {
		perror("Couldn't get adapter");
		return EXIT_FAILURE;
	}

	if (options.verbose) {
		printf("addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
		midi.src_addr.b[5],
		midi.src_addr.b[4],
		midi.src_addr.b[3],
		midi.src_addr.b[2],
		midi.src_addr.b[1],
		midi.src_addr.b[0]);
	}
	midi.src_addr_type = BDADDR_LE_PUBLIC;

	/* TODO: setup adapter*/

	err = midi_init(&midi);
	if (err < 0) {
		perror("Could not initilise GATT Server");
		/* TODO: write a mainloop_clean() ?? */
		return EXIT_FAILURE;
	}

	fd = l2cap_att_setup(&midi.src_addr, midi.src_addr_type);
	if (fd < 0) {
		perror("Error while setting up L2CAP socket");
		goto _cleanup_midi;
	}

	err = mainloop_add_fd(fd, EPOLLIN, l2cap_att_cb, &midi, NULL);
	if (err < 0) {
		perror("Erro adding connection callback to mainloop");
		goto _close_fd;
	}

	if (options.verbose)
		printf("Started listening on ATT channel. Waiting for connections\n");

	err = advertise(&midi);
	if (err < 0)
		goto _remove_fd;

	err = mainloop_run();

_remove_fd:
	mainloop_remove_fd(fd);

_close_fd:
	close(fd);

_cleanup_midi:
	midi_cleanup(&midi);

	return err < 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
