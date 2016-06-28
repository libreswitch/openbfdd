/**************************************************************************
 * Copyright 2016 LinkedIn Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * Author: Ravi Jonnadula
 *
 * File: bfdOvsdbIf.c
 *
 * Purpose: Main file for integrating BFDD with ovsdb and ovs poll-loop.
 *          Its purpose in life is to provide hooks to BFDD daemon to do
 *          following:
 *
 *                1. During start up, read BFDD related
 *                   configuration data and apply to BFDD.
 *
 *                2. During operations, receive administrative
 *                   configuration changes and apply to BFDD config.
 *
 *                3. Update statistics and neighbor tables periodically
 *                   to database.
 *
 *                4. Sync BFDD internal data structures from database
 *                   when restarting BFDD after a crash.
 *
 **************************************************************************/

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>

/*
 * OVS headers
 */
#include "config.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "dummy.h"
#include "fatal-signal.h"
#include "poll-loop.h"
#include "stream.h"
#include "timeval.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"
#include "vswitch-idl.h"
#include "coverage.h"
#include "openswitch-idl.h"
#include "syslog.h"

#include "bfdOvsdbIf.h"
#include "include/bfdCommon.h"

/*
 * Local structure to hold the master thread
 * and counters for read/write callbacks
 */
typedef struct bfd_ovsdb_t_ {
    int enabled;
    void *ovsCmdProc;
    int64_t read_cb_count;
    unsigned int write_cb_count;
} bfd_ovsdb_t;

bfd_ovsdb_t bfd_ovsdb_global;


COVERAGE_DEFINE(bfd_ovsdb_cnt);
VLOG_DEFINE_THIS_MODULE(bfd_ovsdb_if);

#define BUF_LEN 16000
#define MAX_ERR_STR_LEN 255

static struct ovsdb_idl *idl;
static unsigned int idl_seqno;
static int system_configured = false;

static void bfd_ovs_clear_fds(void);
static int bfd_ovspoll_enqueue(void);
static void bfd_ovs_run(void);
static void bfd_ovs_wait(void);

static char *appctl_path = NULL;
static struct unixctl_server *appctl;
static unixctl_cb_func bfd_unixctl_dump;
static unixctl_cb_func bfd_unixctl_exit;

bool exiting = false;


static const struct ovsrec_bfd_session *
find_matching_bfd_session_object(struct ovsdb_idl *idl, const char *remote)
{
	const struct ovsrec_bfd_session *ovs_bfd_session;

	OVSREC_BFD_SESSION_FOR_EACH(ovs_bfd_session, idl) {
		if (strcmp(ovs_bfd_session->bfd_dst_ip, remote) == 0) {
			return ovs_bfd_session;
		}
	}
	return NULL;
}

static const char *
bfd_session_state_enum_to_string(int state)
{
	switch (state) {
		case BFD_OVSDB_IF_SESSION_STATE_ADMIN_DOWN:
			return BFD_OVSDB_IF_SESSION_STATE_STR_ADMIN_DOWN;
		case BFD_OVSDB_IF_SESSION_STATE_DOWN:
			return BFD_OVSDB_IF_SESSION_STATE_STR_DOWN;
		case BFD_OVSDB_IF_SESSION_STATE_INIT:
			return BFD_OVSDB_IF_SESSION_STATE_STR_INIT;
		case BFD_OVSDB_IF_SESSION_STATE_UP:
			return BFD_OVSDB_IF_SESSION_STATE_STR_UP;
		default:
			return "Unknown";
	}
	return NULL;
}

/* Mapping of backend values with OVSDB enums */
static const char *
bfd_session_diag_backend_enum_to_ovsdb_string(int diag_backend_value)
{

	switch (diag_backend_value) {
		case BFD_OVSDB_IF_SESSION_DIAG_NONE:
			return BFD_OVSDB_IF_SESSION_DIAG_STR_NONE;
		case BFD_OVSDB_IF_SESSION_DIAG_CONTROL_DETECT_EXPIRED:
			return BFD_OVSDB_IF_SESSION_DIAG_STR_CONTROL_DETECT_EXPIRED;
		case BFD_OVSDB_IF_SESSION_DIAG_ECHO_FAILED:
			return BFD_OVSDB_IF_SESSION_DIAG_STR_ECHO_FAILED;
		case BFD_OVSDB_IF_SESSION_DIAG_NEIGHBOR_SESSION_DOWN:
			return BFD_OVSDB_IF_SESSION_DIAG_STR_NEIGHBOR_SESSION_DOWN;
		case BFD_OVSDB_IF_SESSION_DIAG_FORWARDING_RESET:
			return BFD_OVSDB_IF_SESSION_DIAG_STR_FORWARDING_RESET;
		case BFD_OVSDB_IF_SESSION_DIAG_PATH_DOWN:
			return BFD_OVSDB_IF_SESSION_DIAG_STR_PATH_DOWN;
		case BFD_OVSDB_IF_SESSION_DIAG_CONCAT_PATH_DOWN:
			return BFD_OVSDB_IF_SESSION_DIAG_STR_CONCAT_PATH_DOWN;
		case BFD_OVSDB_IF_SESSION_DIAG_ADMIN_DOWN:
			return BFD_OVSDB_IF_SESSION_DIAG_STR_ADMIN_DOWN;
		case BFD_OVSDB_IF_SESSION_DIAG_REVERSE_CONCAT_PATH_DOWN:
			return BFD_OVSDB_IF_SESSION_DIAG_STR_REVERSE_CONCAT_PATH_DOWN;
		case BFD_OVSDB_IF_SESSION_DIAG_MAX:
			return BFD_OVSDB_IF_SESSION_DIAG_STR_MAX;
		default:
			return "Unknown";
	}
}

/*
 * Configuration management functions
 */
static bool
bfd_apply_global_changes(struct ovsdb_idl *idl)
{
        const struct ovsrec_system *system_row;
	bfdOvsdbIfGlobal_t bfd_if_global;
	bool is_changed = false;

	system_row = ovsrec_system_first(idl);
        if (!system_row) {
		VLOG_WARN("BFD: Failed to get first system table\n");
		return false;
	}

	memset(&bfd_if_global, 0, sizeof(bfdOvsdbIfGlobal_t));

	if (OVSREC_IDL_IS_COLUMN_MODIFIED(ovsrec_system_col_bfd_enable, idl_seqno)) {
		//bool is_set = (system_row->bfd_enable) ? true : false;

		/* backend hook TBD */
	}

	if (OVSREC_IDL_IS_COLUMN_MODIFIED(ovsrec_system_col_bfd_global_params, idl_seqno)) {
		bfd_if_global.minTxInterval = smap_get_int(&system_row->bfd_global_params,
				BFD_SMAP_KEY_MIN_TX, BFD_GLOBAL_DEFAULT_MIN_TX);
		bfd_if_global.minRxInterval = smap_get_int(&system_row->bfd_global_params,
				BFD_SMAP_KEY_MIN_RX, BFD_GLOBAL_DEFAULT_MIN_RX);
		bfd_if_global.multiplier = smap_get_int(&system_row->bfd_global_params,
				BFD_SMAP_KEY_DECAY_MIN_RX, BFD_GLOBAL_DEFAULT_DECAY_MIN_RX);

		SET_VALID(bfd_if_global.valid, BFD_OVSDB_IF_GLOBAL_MIN_RX_INTERVAL);
		SET_VALID(bfd_if_global.valid, BFD_OVSDB_IF_GLOBAL_MIN_TX_INTERVAL);
		SET_VALID(bfd_if_global.valid, BFD_OVSDB_IF_GLOBAL_MULTIPLIER);
		is_changed = true;
	}

	if (is_changed) {
		VLOG_DBG("BFD changes detected .. applying them now\n");
		// Call the backend wrapper function
		return bfdBackendSetGlobals(bfd_ovsdb_global.ovsCmdProc, &bfd_if_global);
	}

	return false;
}

static void
bfd_apply_session_changes(struct ovsdb_idl *idl)
{
	const struct ovsrec_bfd_session *ovs_bfd_sess;
	bfdOvsdbIfSession_t bfd_if_session;

	OVSREC_BFD_SESSION_FOR_EACH_TRACKED(ovs_bfd_sess, idl) {
		if (ovsrec_bfd_session_row_get_seqno(ovs_bfd_sess, OVSDB_IDL_CHANGE_DELETE) > 0) {
			memset(&bfd_if_session, 0, sizeof(bfdOvsdbIfSession_t));

			bfd_if_session.remote_address = ovs_bfd_sess->bfd_dst_ip;
			bfd_if_session.local_address = ovs_bfd_sess->bfd_src_ip;

			bfd_if_session.action = BFD_OVSDB_IF_SESSION_ACTION_DEL;
			if (!bfdBackendHandleSession(bfd_ovsdb_global.ovsCmdProc, &bfd_if_session)) {
				VLOG_ERR("BFD Failed to delete session: remote(%s) local(%s)\n",
						ovs_bfd_sess->bfd_dst_ip, ovs_bfd_sess->bfd_src_ip);
			}
		} else if (ovsrec_bfd_session_row_get_seqno(ovs_bfd_sess, OVSDB_IDL_CHANGE_INSERT) == 0) {
			memset(&bfd_if_session, 0, sizeof(bfdOvsdbIfSession_t));

			bfd_if_session.remote_address = ovs_bfd_sess->bfd_dst_ip;
			bfd_if_session.local_address = ovs_bfd_sess->bfd_src_ip;

			bfd_if_session.action = BFD_OVSDB_IF_SESSION_ACTION_ADD;
			if (!bfdBackendHandleSession(bfd_ovsdb_global.ovsCmdProc, &bfd_if_session)) {
				VLOG_ERR("BFD Failed to create new session: remote(%s) local(%s)\n",
						ovs_bfd_sess->bfd_dst_ip, ovs_bfd_sess->bfd_src_ip);
			}
		} else if (ovsrec_bfd_session_row_get_seqno(ovs_bfd_sess, OVSDB_IDL_CHANGE_MODIFY) == 0) {
			memset(&bfd_if_session, 0, sizeof(bfdOvsdbIfSession_t));

			bfd_if_session.remote_address = ovs_bfd_sess->bfd_dst_ip;
			bfd_if_session.local_address = ovs_bfd_sess->bfd_src_ip;

			bfd_if_session.action = BFD_OVSDB_IF_SESSION_ACTION_MODIFY;
			if (!bfdBackendHandleSession(bfd_ovsdb_global.ovsCmdProc, &bfd_if_session)) {
				VLOG_ERR("BFD Failed to modify session: remote(%s) local(%s)\n",
						ovs_bfd_sess->bfd_dst_ip, ovs_bfd_sess->bfd_src_ip);
			}
		}
	}

	/* All changes processed - clear the change track */
	ovsdb_idl_track_clear(idl);

	return;
}


static void
bfd_ovs_clear_fds()
{
	struct poll_loop *loop = poll_loop();

	free_poll_nodes(loop);
	loop->timeout_when = LLONG_MAX;
	loop->timeout_where = NULL;
}

static int
bfd_ovspoll_enqueue(void)
{
	struct poll_loop *loop = poll_loop();
	struct poll_node *node;
	int flags;
	fd_set waitOn;
	uint32_t pollTimeInMs = 100;
	struct timeval waitTime;

	int events_scheduled = 0;

	/* Populate with all the fds events. */
	HMAP_FOR_EACH(node, hmap_node, &loop->poll_nodes) {
		if ((flags = fcntl(node->pollfd.fd, F_GETFL, NULL)) >= 0) {
			if (!(flags & O_NONBLOCK)) {
				if (fcntl(node->pollfd.fd, F_SETFL, flags | O_NONBLOCK) == -1) {
					/* Failed to set fd into non-blocking mode */
					continue;
				}
			}

			waitTime.tv_sec = pollTimeInMs / 1000;
			waitTime.tv_usec = (pollTimeInMs % 1000) * 1000;

			FD_ZERO(&waitOn);
			FD_SET(node->pollfd.fd, &waitOn);
			if ( select(node->pollfd.fd + 1, &waitOn, NULL, NULL, &waitTime) > 0 ) {
				events_scheduled++;
			}
		}
	}

	if (events_scheduled)
		return 0;

	/* Nothing was scheduled, return -1 */
	return -1;
}

void
bfd_ovsdb_init_poll_loop(void)
{
	if (!bfd_ovsdb_global.enabled) {
		VLOG_ERR("OVS not enabled for BFD. Return\n");
		return;
	}

	bfd_ovs_clear_fds();
	bfd_ovs_run();
	bfd_ovs_wait();
	bfd_ovspoll_enqueue();
#if 0
	poll_block();
#endif
	return;
}

static void
bfd_reconfigure(struct ovsdb_idl *idl)
{
	unsigned int new_idl_seqno = ovsdb_idl_get_seqno(idl);

	COVERAGE_INC(bfd_ovsdb_cnt);

	if (new_idl_seqno == idl_seqno) {
		VLOG_DBG("No config change for BFD in ovs\n");
		return;
	}

	// BFD global table
	bfd_apply_global_changes(idl);

	// BFD session table
	bfd_apply_session_changes(idl);

	// update the seq. number
	idl_seqno = new_idl_seqno;

	return;
}


/*
 * Function       : bfd_dump
 * Responsibility : populates buffer for unixctl reply
 * Parameters     : buffer , buffer length
 * Returns        : void
 */

static void
bfd_dump(char* ATTR_UNUSED(buf), int ATTR_UNUSED(buflen))
{
}

static void
bfd_unixctl_dump(struct unixctl_conn *conn, int argc OVS_UNUSED,
		const char *argv[]OVS_UNUSED, void *aux OVS_UNUSED)
{
	char err_str[MAX_ERR_STR_LEN];
	char *buf = xcalloc(1, BUF_LEN);
	if (buf){
		bfd_dump(buf,BUF_LEN);
		unixctl_command_reply(conn, buf);
		free(buf);
	} else {
		snprintf(err_str,sizeof(err_str),
				"bfdd daemon failed to allocate %d bytes", BUF_LEN );
		unixctl_command_reply(conn, err_str );
	}
	return;
}


static void
bfd_unixctl_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
	       const char *argv[]OVS_UNUSED, void *exiting_)
{
	bool *exiting = exiting_;

	*exiting = true;
	unixctl_command_reply(conn, NULL);
}

static inline void
bfd_chk_for_system_configured(void)
{
	const struct ovsrec_system *ovs_vsw = NULL;

	if (system_configured) {
		/* Nothing to do if bfdd is already configured. */
		return;
	}

	ovs_vsw = ovsrec_system_first(idl);
	if (ovs_vsw && (ovs_vsw->cur_cfg > (int64_t) 0)) {
		system_configured = true;
		VLOG_INFO("System is now configured (cur_cfg=%d).", (int) ovs_vsw->cur_cfg);
	}
}

/*****************************************************************************
 * poll/run/timer functions
 *****************************************************************************/
static void
bfd_ovs_run(void)
{
	ovsdb_idl_run(idl);
	unixctl_server_run(appctl);

	if (ovsdb_idl_is_lock_contended(idl)) {
		static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
		VLOG_ERR_RL(&rl, "another BFD process is running, "
			    "disabling this process until it goes away");
		return;
	} else if (!ovsdb_idl_has_lock(idl)) {
		VLOG_DBG("bfd_ovs_run(): failed to obtain lock");
		return;
	}

	bfd_chk_for_system_configured();

	if (system_configured) {
		bfd_reconfigure(idl);
		daemonize_complete();
		vlog_enable_async();
		VLOG_INFO_ONCE("%s (OPENSWITCH bfdd) %s", program_name, VERSION);
	}

	return;
}

static void
bfd_ovs_wait(void)
{
	ovsdb_idl_wait(idl);
	unixctl_server_wait(appctl);
}

/*
 * Create a connection to the OVSDB at db_path and create a dB cache
 * for this daemon.
 */
static void
bfd_ovsdb_table_init(void)
{
        /* Registering BFD Global table */
        ovsdb_idl_add_table(idl, &ovsrec_table_system);
	ovsdb_idl_add_column(idl, &ovsrec_system_col_bfd_enable);
	//ovsdb_idl_track_add_column(idl, &ovsrec_system_col_bfd_enable);
	ovsdb_idl_add_column(idl, &ovsrec_system_col_bfd_global_params);
	//ovsdb_idl_track_add_column(idl, &ovsrec_system_col_bfd_global_params);

        /* BFD Session table */
        ovsdb_idl_add_table(idl, &ovsrec_table_bfd_session);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_remote_multiplier);
	ovsdb_idl_omit_alert(idl, &ovsrec_bfd_session_col_remote_multiplier);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_remote_state);
	ovsdb_idl_omit_alert(idl, &ovsrec_bfd_session_col_remote_state);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_remote_diagnostic);
	ovsdb_idl_omit_alert(idl, &ovsrec_bfd_session_col_remote_diagnostic);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_effective_min_tx_interval);
	ovsdb_idl_omit_alert(idl, &ovsrec_bfd_session_col_effective_min_tx_interval);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_from);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_forwarding);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_bfd_src_ip);
	ovsdb_idl_track_add_column(idl, &ovsrec_bfd_session_col_bfd_src_ip);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_decay_min_rx);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_bfd_local_dst_mac);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_state);
	ovsdb_idl_omit_alert(idl, &ovsrec_bfd_session_col_state);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_remote_discriminator);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_min_tx);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_forwarding_if_rx);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_min_rx);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_effective_min_rx_interval);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_enable);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_check_tnl_key);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_diagnostic);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_bfd_remote_dst_mac);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_remote_min_rx_interval);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_local_discriminator);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_bfd_local_src_mac);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_bfd_dst_ip);
	ovsdb_idl_track_add_column(idl, &ovsrec_bfd_session_col_bfd_dst_ip);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_flap_count);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_remote_min_tx_interval);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_session_id);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_cpath_down);
}

static void
bfd_ovs_init(const char *db_path)
{
	/* Initialize IDL through a new connection to the dB */
	idl = ovsdb_idl_create(db_path, &ovsrec_idl_class, false, true);
	idl_seqno = ovsdb_idl_get_seqno(idl);
	ovsdb_idl_set_lock(idl, "ops_bfdd");

	/* Choose some OVSDB tables and columns to cache */

	/* Cache OpenVSwitch table */
	ovsdb_idl_add_table(idl, &ovsrec_table_system);

	ovsdb_idl_add_column(idl, &ovsrec_system_col_cur_cfg);
	ovsdb_idl_add_column(idl, &ovsrec_system_col_hostname);

	/* BFD Tables */
	bfd_ovsdb_table_init();

	/* Register ovs-appctl commands for this daemon */
	unixctl_command_register("bfd/dump", "", 0, 0, bfd_unixctl_dump, NULL);
}

static void
usage(void)
{
	printf("%s: OPENSWITCH bfdd daemon\n"
	       "usage: %s [OPTIONS] [DATABASE]\n"
	       "where DATABASE is a socket on which ovsdb-server is listening\n"
	       "      (default: \"unix:%s/db.sock\").\n",
	       program_name, program_name, ovs_rundir());
	stream_usage("DATABASE", true, false, true);
	daemon_usage();
	vlog_usage();
	printf("\nOther options:\n"
	       "  --unixctl=SOCKET        override default control socket name\n"
	       "  -h, --help              display this help message\n"
	       "  -V, --version           display version information\n");
	exit(EXIT_SUCCESS);
}

static char *
bfd_ovsdb_parse_options(int argc, char *argv[], char **unixctl_pathp)
{
	enum {
		OPT_UNIXCTL = UCHAR_MAX + 1,
		VLOG_OPTION_ENUMS,
		DAEMON_OPTION_ENUMS,
		OVSDB_OPTIONS_END,
	};

	static const struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"unixctl", required_argument, NULL, OPT_UNIXCTL},
		DAEMON_LONG_OPTIONS,
		VLOG_LONG_OPTIONS,
		{"ovsdb-options-end", optional_argument, NULL, OVSDB_OPTIONS_END},
		{NULL, 0, NULL, 0},
	};
	char *short_options = long_options_to_short_options(long_options);

	for (;;) {
		int c;
		int end_options = 0;

		c = getopt_long(argc, argv, short_options, long_options, NULL);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			usage();

		case OPT_UNIXCTL:
			*unixctl_pathp = optarg;
			break;

			VLOG_OPTION_HANDLERS
			DAEMON_OPTION_HANDLERS

		case OVSDB_OPTIONS_END:
			end_options = 1;
			break;

		case '?':
			exit(EXIT_FAILURE);

		default:
			abort();
		}
		if (end_options)
			break;
	}
	free(short_options);

	argc -= optind;
	argv += optind;

	return xasprintf("unix:%s/db.sock", ovs_rundir());
}

void
bfd_ovsdb_init(int argc, char *argv[])
{
	int retval;
	char *ovsdb_sock;

	VLOG_INFO("Initializing BFD OVSDB");

	memset(&bfd_ovsdb_global, 0, sizeof(bfd_ovsdb_t));

	set_program_name(argv[0]);
	proctitle_init(argc, argv);
	fatal_ignore_sigpipe();

	/* Parse commandline args and get the name of the OVSDB socket */
	ovsdb_sock = bfd_ovsdb_parse_options(argc, argv, &appctl_path);

	/* Initialize the metadata for the IDL cache */
	ovsrec_init();
	/*
	 * Fork and return in child process; but don't notify parent of
	 * startup completion yet.
	 */
	daemonize_start();

	/* Create UDS connection for ovs-appctl */
	retval = unixctl_server_create(appctl_path, &appctl);
	if (retval) {
		exit(EXIT_FAILURE);
	}

	/* Register the ovs-appctl "exit" command for this daemon */
	unixctl_command_register("exit", "", 0, 0, bfd_unixctl_exit, &exiting);

	/* Create the IDL cache of the dB at ovsdb_sock */
	bfd_ovs_init(ovsdb_sock);
	free(ovsdb_sock);

	/* Notify parent of startup completion */
	daemonize_complete();

	/* Enable asynch log writes to disk */
	vlog_enable_async();

	VLOG_INFO_ONCE("%s (OpenSwitch BFD Daemon) started", program_name);

	bfd_ovsdb_global.enabled = 1;
	return;
}

void
bfd_ovsdb_init_context(void *ovsCmdProc)
{
	bfd_ovsdb_global.ovsCmdProc = ovsCmdProc;
	return;
}

void
bfd_ovsdb_exit(void)
{
	ovsdb_idl_destroy(idl);
}

// BFD to DB update handler
bool
bfdOvsdbIfUpdateSession(bfdOvsdbIfSession_t *bfd_if_session)
{
	struct ovsdb_idl_txn *db_txn;
	enum ovsdb_idl_txn_status txn_status;
	const struct ovsrec_bfd_session *ovs_bfd_session;

	ovs_bfd_session = find_matching_bfd_session_object(idl, bfd_if_session->remote_address);
	if (!ovs_bfd_session) {
		VLOG_ERR("BFD Session for %s not found in DB\n", bfd_if_session->remote_address);
		return false;
	}

	db_txn = ovsdb_idl_txn_create(idl);
	if (NULL == db_txn) {
		VLOG_ERR("BFD DB transaction create failed: Cannot update Session status for %s\n",
				bfd_if_session->remote_address);
		return false;
	}

	if (IS_VALID(bfd_if_session->valid, BFD_OVSDB_IF_SESSION_VALID_LOCAL_STATE)) {
		VLOG_DBG("Updating BFD Session(%s) local state to %d:%s\n",
				bfd_if_session->remote_address, bfd_if_session->local_state,
				bfd_session_state_enum_to_string(bfd_if_session->local_state));
		ovsrec_bfd_session_set_state(ovs_bfd_session, bfd_session_state_enum_to_string(bfd_if_session->local_state));
	}

	if (IS_VALID(bfd_if_session->valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_STATE)) {
		VLOG_DBG("Updating BFD Session(%s) remote state to %d:%s\n",
				bfd_if_session->remote_address, bfd_if_session->remote_state,
				bfd_session_state_enum_to_string(bfd_if_session->remote_state));
		ovsrec_bfd_session_set_remote_state(ovs_bfd_session, bfd_session_state_enum_to_string(bfd_if_session->remote_state));
	}

	if (IS_VALID(bfd_if_session->valid, BFD_OVSDB_IF_SESSION_VALID_LOCAL_DIAG)) {
		ovsrec_bfd_session_set_diagnostic(ovs_bfd_session,
				bfd_session_diag_backend_enum_to_ovsdb_string(bfd_if_session->local_diag));
	}

	if (IS_VALID(bfd_if_session->valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_MULTI)) {
		ovsrec_bfd_session_set_remote_multiplier(ovs_bfd_session, bfd_if_session->remoteMultiplier);
	}

	if (IS_VALID(bfd_if_session->valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_MIN_TX)) {
		ovsrec_bfd_session_set_remote_min_tx_interval(ovs_bfd_session, bfd_if_session->remoteMinTxInterval);
	}

	if (IS_VALID(bfd_if_session->valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_MIN_RX)) {
		ovsrec_bfd_session_set_remote_min_rx_interval(ovs_bfd_session, bfd_if_session->remoteMinRxInterval);
	}

	if (IS_VALID(bfd_if_session->valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_DIAG)) {
		ovsrec_bfd_session_set_remote_diagnostic(ovs_bfd_session,
				bfd_session_diag_backend_enum_to_ovsdb_string(bfd_if_session->remote_diag));
	}

	if (IS_VALID(bfd_if_session->valid, BFD_OVSDB_IF_SESSION_VALID_TRANSMIT_INTERVAL)) {
		ovsrec_bfd_session_set_effective_min_tx_interval(ovs_bfd_session, bfd_if_session->transmitInterval);
	}

	if (IS_VALID(bfd_if_session->valid, BFD_OVSDB_IF_SESSION_VALID_DETECTION_TIME)) {
		ovsrec_bfd_session_set_effective_min_rx_interval(ovs_bfd_session, bfd_if_session->detectionTime);
	}

#if 1
	/* For some strange reason, the second DB update is getting lost
	   when two consecutive writes are done ... To, workaround this
	   let's commit the change in a blocking manner for now...
	   optimize it later */
	txn_status = ovsdb_idl_txn_commit_block(db_txn);
#else
	txn_status = ovsdb_idl_txn_commit(db_txn);
#endif
	syslog(LOG_ERR, "transaction result = %d \n", txn_status);
	ovsdb_idl_txn_destroy(db_txn);
	return true;
}
