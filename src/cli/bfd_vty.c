/**************************************************************************
 * Copyright (c) 2016 LinkedIn Corp.
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
 * Purpose: BFD CLI implementation with OPS vtysh.
 **************************************************************************/

#include <stdio.h>
#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "vtysh/command.h"
#include "vtysh/memory.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/vtysh_utils.h"
#include "vtysh/utils/ovsdb_vtysh_utils.h"
#include "vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "ovsdb-idl.h"

#include "bfd_vty.h"
#include "bfdCommon.h"
#include "vtysh_ovsdb_bfd_context.h"

extern struct ovsdb_idl *idl;

VLOG_DEFINE_THIS_MODULE(vtysh_bfd_cli);


#define ERR_BUF_LEN 128
#define MSG_LEN     64

/********************** Simple error handling ***********************/

/*
 * Depending on the outcome of the db transaction, returns
 * the appropriate value for the cli command execution.
 */
static const char *_undefined = "undefined";
static char itoa_buffer [MSG_LEN];

static char *
safe_print_string(size_t count, char *string)
{
    if ((count > 0) && string) {
        return string;
    }
    return (char*)_undefined;
}

static char *
safe_print_integer(size_t count, const int64_t *iptr)
{
    if ((count > 0) && iptr) {
        snprintf(itoa_buffer, MSG_LEN, "%"PRId64, *iptr);
        return itoa_buffer;
    }
    return (char*)_undefined;
}

static bool
string_is_an_ip_address(const char *string)
{
    union sockunion su;
    return (str2sockunion(string, &su) >= 0);
}

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

static int
cli_bfd_global_enable_cmd_execute(bool enable)
{
    const struct ovsrec_system *system_row = NULL;
    struct ovsdb_idl_txn* ovsdb_txn = NULL;
    const bool bfd_enable = true;

    /* Start of transaction. */
    START_DB_TXN(ovsdb_txn);

    system_row = ovsrec_system_first(idl);
    if(!system_row)
    {
        VLOG_ERR("\nBFD: OVSDB failed to fetch System entry\n");
        ERRONEOUS_DB_TXN(ovsdb_txn, "%% Failed to enable BFD globally\n");
    }

    if (enable)
    {
        ovsrec_system_set_bfd_enable(system_row, &bfd_enable, 1);
    }
    else
    {
        ovsrec_system_set_bfd_enable(system_row, NULL, 0);
    }

    /* End of transaction. */
    END_DB_TXN(ovsdb_txn);

    return CMD_SUCCESS;
}

static int
cli_bfd_global_timers_cmd_execute(const char *interval, const char *min_rx, const char *multiplier)
{
    const struct ovsrec_system *system_row = NULL;
    struct smap smap = SMAP_INITIALIZER(&smap);
    struct ovsdb_idl_txn* ovsdb_txn = NULL;

    /* Start of transaction. */
    START_DB_TXN(ovsdb_txn);

    system_row = ovsrec_system_first(idl);
    if(!system_row)
    {
        VLOG_ERR("\nBFD: OVSDB failed to fetch System entry\n");
        ERRONEOUS_DB_TXN(ovsdb_txn, "%% Failed to configure BFD global timers\n");
    }

    smap_clone(&smap, &system_row->bfd_global_params);
    smap_replace(&smap, BFD_SMAP_KEY_MIN_TX, interval);
    smap_replace(&smap, BFD_SMAP_KEY_MIN_RX, min_rx);
    smap_replace(&smap, BFD_SMAP_KEY_DECAY_MIN_RX, multiplier);

    ovsrec_system_set_bfd_global_params(system_row, &smap);
    smap_destroy(&smap);

    /* End of transaction. */
    END_DB_TXN(ovsdb_txn);

    return CMD_SUCCESS;
}

static int
cli_bfd_session_cmd_execute(const char *remote_str, const char *local_str)
{
    const struct ovsrec_bfd_session *ovs_bfd_session;
    struct ovsdb_idl_txn *ovsdb_txn;
    char error_message[ERR_BUF_LEN];
    char *from = "static";

    if (!string_is_an_ip_address(remote_str)) {
        VLOG_ERR("\nInvalid remote address %s\n", remote_str);
        return CMD_WARNING;
    }

    if (!string_is_an_ip_address(local_str)) {
        VLOG_ERR("\nInvalid local address %s\n", local_str);
        return CMD_WARNING;
    }

    /* Start of transaction. */
    START_DB_TXN(ovsdb_txn);

    ovs_bfd_session = find_matching_bfd_session_object(idl, remote_str);
    if (ovs_bfd_session) {
        VLOG_ERR("\nBFD Session for remote %s already exists!\n", remote_str);
        snprintf(error_message, ERR_BUF_LEN, "%% BFD Session for remote %s already exists\n", remote_str);
        ABORT_DB_TXN(ovsdb_txn, error_message);
    }


    ovs_bfd_session = ovsrec_bfd_session_insert(ovsdb_txn);
    if (!ovs_bfd_session) {
        VLOG_ERR("\nFailed to create BFD Session for remote %s local %s\n", remote_str, local_str);
        ERRONEOUS_DB_TXN(ovsdb_txn, "%% Failed to create BFD Session\n");
    }

    ovsrec_bfd_session_set_bfd_dst_ip(ovs_bfd_session, remote_str);
    ovsrec_bfd_session_set_bfd_src_ip(ovs_bfd_session, local_str);
    ovsrec_bfd_session_set_from(ovs_bfd_session, from);

    /* End of transaction. */
    END_DB_TXN(ovsdb_txn);

    return CMD_SUCCESS;
}

static int
cli_no_bfd_session_cmd_execute(const char *remote_str, const char *local_str)
{
    const struct ovsrec_bfd_session *ovs_bfd_session;
    struct ovsdb_idl_txn *ovsdb_txn;
        char error_message[ERR_BUF_LEN];

    if (!string_is_an_ip_address(remote_str)) {
        VLOG_ERR("\nInvalid remote address %s\n", remote_str);
        return CMD_WARNING;
    }

    if (!string_is_an_ip_address(local_str)) {
        VLOG_ERR("\nInvalid local address %s\n", local_str);
        return CMD_WARNING;
    }

    /* Start of transaction. */
    START_DB_TXN(ovsdb_txn);

    ovs_bfd_session = find_matching_bfd_session_object(idl, remote_str);
    if (!ovs_bfd_session) {
        VLOG_ERR("\nBFD Session for remote %s not found\n", remote_str);
        snprintf(error_message, ERR_BUF_LEN, "%% BFD Session for remote %s not found\n", remote_str);
        ABORT_DB_TXN(ovsdb_txn, error_message);
    }

    ovsrec_bfd_session_delete(ovs_bfd_session);

    /* End of transaction. */
    END_DB_TXN(ovsdb_txn);

    return CMD_SUCCESS;
}

static int
show_bfd_cmd_execute(struct vty *vty)
{
    const struct ovsrec_system *system_row;

    system_row = ovsrec_system_first(idl);
    if(system_row)
    {
        if (system_row->n_bfd_enable > 0) {
            vty_out(vty, "BFD Status: %s\n", "Enable");
        } else {
            vty_out(vty, "BFD Status : Disable\n");
        }

        vty_out(vty, "  Interval   : %d\n",
                smap_get_int(&system_row->bfd_global_params,
                    BFD_SMAP_KEY_MIN_TX, BFD_GLOBAL_DEFAULT_MIN_TX));
        vty_out(vty, "  Min Rx     : %d\n",
            smap_get_int(&system_row->bfd_global_params,
                BFD_SMAP_KEY_MIN_RX, BFD_GLOBAL_DEFAULT_MIN_RX));
        vty_out(vty, "  Multiplier : %d\n",
            smap_get_int(&system_row->bfd_global_params,
                BFD_SMAP_KEY_DECAY_MIN_RX, BFD_GLOBAL_DEFAULT_DECAY_MIN_RX));
    }

    return CMD_SUCCESS;
}

static void
show_bfd_session_brief_header(struct vty *vty)
{
    vty_out(vty, "----------------------------------------"
         "-----------------------------------------%s", VTY_NEWLINE);
    vty_out(vty, "%15s %15s %15s %32s%s",
            "Remote Address", "Local Address", "State", "Diagnostics",
            VTY_NEWLINE);
    vty_out(vty, "%15s %15s %15s %32s%s",
            " ", " ", "(Remote/Local)", "(Remote/Local)", VTY_NEWLINE);
    vty_out(vty, "----------------------------------------"
         "-----------------------------------------%s", VTY_NEWLINE);
}

static int
show_bfd_session_brief(struct vty *vty)
{
    const struct ovsrec_bfd_session *ovs_bfd_session;
    bool header = true;
    char state[MSG_LEN];
    char diags[MSG_LEN];

    OVSREC_BFD_SESSION_FOR_EACH(ovs_bfd_session, idl) {
    if (header) {
        show_bfd_session_brief_header(vty);
        header = false;
    }

    snprintf(state, MSG_LEN, "%s/%s",
            ((ovs_bfd_session->remote_state) ?
             safe_print_string(1, ovs_bfd_session->remote_state) :
             "--"),
            ((ovs_bfd_session->state) ?
             safe_print_string(1, ovs_bfd_session->state) : "--"));

    snprintf(diags, MSG_LEN, "%s/%s",
            safe_print_string(1, ovs_bfd_session->remote_diagnostic),
            safe_print_string(1, ovs_bfd_session->diagnostic));

    vty_out(vty, "%15s %15s %15s %32s%s",
            ((ovs_bfd_session->bfd_dst_ip) ?
             safe_print_string(1, ovs_bfd_session->bfd_dst_ip) : "--"),
            ((ovs_bfd_session->bfd_src_ip) ?
             safe_print_string(1, ovs_bfd_session->bfd_src_ip) : "--"),
            state, diags, VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

static int
show_bfd_session_detail(struct vty *vty)
{
    const struct ovsrec_bfd_session *ovs_bfd_session;

    OVSREC_BFD_SESSION_FOR_EACH(ovs_bfd_session, idl) {
        if(ovs_bfd_session->bfd_dst_ip) {
            vty_out(vty, "  Neighbor address : %s (Originator: %s)\n",
                    safe_print_string(1, ovs_bfd_session->bfd_dst_ip),
                    ((ovs_bfd_session->from) ?
                     safe_print_string(1, ovs_bfd_session->from) :
                     "Unknown"));
        }

        if(ovs_bfd_session->bfd_src_ip) {
            vty_out(vty, "    Local address : %s\n",
                    safe_print_string(1, ovs_bfd_session->bfd_src_ip));
        }

        if(ovs_bfd_session->remote_state) {
            vty_out(vty, "    Remote state : %s <%s>\n",
                    safe_print_string(1, ovs_bfd_session->remote_state),
                    safe_print_string(1, ovs_bfd_session->remote_diagnostic));
        }

        if(ovs_bfd_session->state) {
            vty_out(vty, "    Local state : %s <%s>\n",
                    safe_print_string(1, ovs_bfd_session->state),
                    safe_print_string(1, ovs_bfd_session->diagnostic));
        }

        if(ovs_bfd_session->effective_min_tx_interval) {
            vty_out(vty, "    Local Tx Interval : %s\n",
                    safe_print_integer(1, &ovs_bfd_session->effective_min_tx_interval));
        }

        if(ovs_bfd_session->effective_min_rx_interval) {
            vty_out(vty, "    Local Rx Timeout : %s\n",
                    safe_print_integer(1, &ovs_bfd_session->effective_min_rx_interval));
        }

        if(ovs_bfd_session->remote_multiplier) {
            vty_out(vty, "    Remote detect multiplier : %s\n",
                    safe_print_integer(1, &ovs_bfd_session->remote_multiplier));
        }

        if(ovs_bfd_session->remote_min_tx_interval) {
            vty_out(vty, "    Remote desired minimum Tx Interval : %s\n",
                    safe_print_integer(1, &ovs_bfd_session->remote_min_tx_interval));
        }

        if(ovs_bfd_session->remote_min_rx_interval) {
            vty_out(vty, "    Remote required minimum Rx Interval : %s\n",
                    safe_print_integer(1, &ovs_bfd_session->remote_min_rx_interval));
        }


        // TBD more state info

        vty_out(vty,"\n");
    }

    return CMD_SUCCESS;
}

static int
show_bfd_session_cmd_execute(struct vty *vty, bool detailed)
{
    if (detailed)
        return show_bfd_session_detail(vty);

    return show_bfd_session_brief(vty);
}

DEFUN(bfd_global_enable,
      bfd_global_enable_cmd,
      "bfd enable",
      "BFD specific commands"
      "Enable\n")
{
    cli_bfd_global_enable_cmd_execute(true);
    return CMD_SUCCESS;
}

DEFUN(no_bfd_global_enable,
      no_bfd_global_enable_cmd,
      "no bfd enable",
      NO_STR
      "BFD specific commands"
      "Enable\n")
{
    cli_bfd_global_enable_cmd_execute(false);
    return CMD_SUCCESS;
}

DEFUN(bfd_global_timers,
      bfd_global_timers_cmd,
      "bfd interval <15-300000> min_rx <15-300000> multiplier <0-255>",
      "BFD specific commands"
      "Transmit interval\n"
      "Allowed range <15-300000> milliseconds (Default: 15)\n"
      "Minimum receive interval\n"
      "Allowed range <15-300000> milliseconds (Default: 15)\n"
      "Multiplier\n"
      "Allowed range <1-255> (Default: 3)\n")
{
    cli_bfd_global_timers_cmd_execute(argv[0], argv[1], argv[2]);
    return CMD_SUCCESS;
}


#ifdef HAVE_IPV6
DEFUN(bfd_session,
      bfd_session_cmd,
      "bfd session remote (A.B.C.D|X:X::X:X|WORD) local (A.B.C.D|X:X::X:X|WORD)",
      "BFD specific commands"
      "Session\n"
      "Remote\n"
      "Remote address\nRemote IPv6 address\nWord\n"
      "Local\n"
      "Local address\nLocal IPv6 address\nWord\n")
#else
DEFUN(bfd_session,
      bfd_session_cmd,
      "bfd session remote A.B.C.D local A.B.C.D",
      "BFD specific commands"
      "Session\n"
      "Remote\n"
      "Remote address\n"
      "Local\n"
      "Local address\n")
#endif
{
    cli_bfd_session_cmd_execute(argv[0], argv[1]);
    return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
DEFUN(no_bfd_session,
      no_bfd_session_cmd,
      "no bfd session remote (A.B.C.D|X:X::X:X|WORD) local (A.B.C.D|X:X::X:X|WORD)",
      NO_STR
      "BFD specific commands"
      "Session\n"
      "Remote\n"
      "Remote address\nRemote IPv6 address\nWord\n"
      "Local\n"
      "Local address\nLocal IPv6 address\nWord\n")
#else
DEFUN(no_bfd_session,
      no_bfd_session_cmd,
      "no bfd session remote A.B.C.D local A.B.C.D",
      NO_STR
      "BFD specific commands"
      "Session\n"
      "Remote\n"
      "Remote address\n"
      "Local\n"
      "Local address\n")
#endif
{
        cli_no_bfd_session_cmd_execute(argv[0], argv[1]);
        return CMD_SUCCESS;
}

DEFUN(vtysh_show_bfd,
      vtysh_show_bfd_cmd,
      "show bfd",
       SHOW_STR
       "BFD specific commands")
{
    show_bfd_cmd_execute(vty);
    show_bfd_session_cmd_execute(vty, false);
    return CMD_SUCCESS;
}


DEFUN(vtysh_show_bfd_session,
      vtysh_show_bfd_session_cmd,
      "show bfd neighbors {detail}",
      SHOW_STR
      "BFD specific commands"
      NEIGHBOR_STR
      "detail\n")
{
    bool detail = false;

    if ((argv[1] != NULL) && (strcmp(argv[1], "detail") == 0))
        detail = true;

    show_bfd_session_cmd_execute(vty, detail);
    return CMD_SUCCESS;
}

static void
bfd_ovsdb_init()
{
        /* Registering BFD Global table */
        ovsdb_idl_add_table(idl, &ovsrec_table_system);
        ovsdb_idl_add_column(idl, &ovsrec_system_col_bfd_enable);
        ovsdb_idl_add_column(idl, &ovsrec_system_col_bfd_global_params);

        /* BFD Session table */
        ovsdb_idl_add_table(idl, &ovsrec_table_bfd_session);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_remote_multiplier);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_remote_state);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_remote_diagnostic);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_effective_min_tx_interval);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_from);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_forwarding);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_bfd_src_ip);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_decay_min_rx);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_bfd_local_dst_mac);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_state);
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
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_flap_count);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_remote_min_tx_interval);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_session_id);
        ovsdb_idl_add_column(idl, &ovsrec_bfd_session_col_cpath_down);
}

void cli_pre_init(void)
{
    bfd_ovsdb_init();
}

void
cli_post_init(void)
{
    vtysh_ret_val retval = e_vtysh_error;

    /* Show bgp command */
    install_element(ENABLE_NODE, &vtysh_show_bfd_session_cmd);
    install_element(VIEW_NODE, &vtysh_show_bfd_session_cmd);

    install_element(ENABLE_NODE, &vtysh_show_bfd_cmd);
    install_element(VIEW_NODE, &vtysh_show_bfd_cmd);

    /* Global configuration commands */
    install_element(CONFIG_NODE, &bfd_global_enable_cmd);
    install_element(CONFIG_NODE, &no_bfd_global_enable_cmd);
    install_element(CONFIG_NODE, &bfd_global_timers_cmd);
    install_element(CONFIG_NODE, &bfd_session_cmd);
    install_element(CONFIG_NODE, &no_bfd_session_cmd);

    retval = install_show_run_config_subcontext(e_vtysh_config_context,
            e_vtysh_config_context_bfd,
            &vtysh_config_context_bfd_clientcallback,
            NULL, NULL);
    if(e_vtysh_ok != retval)
    {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                "Unable to add BFD context callback");
        assert(0);
    }
}
