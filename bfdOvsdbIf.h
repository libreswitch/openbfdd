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
 * Purpose: This file includes all public interface defines needed by
 *          the new bfd_ovsdb_if.c for bfd - ovsdb integration
 **************************************************************************/

#ifndef BFD_OVSDB_IF_H
#define BFD_OVSDB_IF_H 1

#ifdef __cplusplus
extern "C" {
#endif


/* Setup bfdd to connect with ovsdb and daemonize. This daemonize is used
 * over the daemonize in the main function to keep the behavior consistent
 * with the other daemons in the OpenSwitch system
 */
void bfd_ovsdb_init(int argc, char *argv[]);
void bfd_ovsdb_init_context(void *ovsCmdProc);

/* When the daemon is ready to shut, delete the idl cache
 * This happens with the ovs-appctl exit command.
 */
void bfd_ovsdb_exit(void);

/*
** Original names are soo long.. exceeds 80 chars,
** shorten them a bit
*/
#define ANY_NEW_ROW			OVSREC_IDL_ANY_TABLE_ROWS_INSERTED
#define ANY_ROW_CHANGED			OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED
#define ANY_ROW_DELETED			OVSREC_IDL_ANY_TABLE_ROWS_DELETED
#define NEW_ROW				OVSREC_IDL_IS_ROW_INSERTED
#define ROW_CHANGED			OVSREC_IDL_IS_ROW_MODIFIED
/* row is not used now but may be in the future */
#define COL_CHANGED(row, col, s)	OVSREC_IDL_IS_COLUMN_MODIFIED(col, s)

/* Initialize and integrate the ovs poll loop with the daemon */
void bfd_ovsdb_init_poll_loop(void);


#define IS_VALID(_V_, _P_)      ((_V_) & (0x1 << (_P_)))
#define SET_VALID(_V_, _P_)     {(_V_) |= (0x1 << (_P_));}

typedef struct bfdOvsdbIfGlobal_s
{
  uint32_t minTxInterval;
  uint32_t minRxInterval;
  uint8_t  multiplier;

  uint8_t  valid;
#define BFD_OVSDB_IF_GLOBAL_MIN_TX_INTERVAL	0
#define BFD_OVSDB_IF_GLOBAL_MIN_RX_INTERVAL	1
#define BFD_OVSDB_IF_GLOBAL_MULTIPLIER		2
} bfdOvsdbIfGlobal_t;

bool bfdBackendSetGlobals(void *bea, bfdOvsdbIfGlobal_t *bfd_if_global);


typedef struct bfdOvsdbIfSession_s
{
  uint64_t sessionId;
  char *remote_address;
  char *local_address;

  int remote_state;
  int local_state;
#define BFD_OVSDB_IF_SESSION_STATE_ADMIN_DOWN	0 // must match bfd::State::Value && ovsrec_bfd_session_state
#define BFD_OVSDB_IF_SESSION_STATE_DOWN		1 // must match bfd::State::Value && ovsrec_bfd_session_state
#define BFD_OVSDB_IF_SESSION_STATE_INIT		2 // must match bfd::State::Value && ovsrec_bfd_session_state
#define BFD_OVSDB_IF_SESSION_STATE_UP		3 // must match bfd::State::Value && ovsrec_bfd_session_state

#define BFD_OVSDB_IF_SESSION_STATE_STR_ADMIN_DOWN	"admin_down"
#define BFD_OVSDB_IF_SESSION_STATE_STR_DOWN		"down"
#define BFD_OVSDB_IF_SESSION_STATE_STR_INIT		"init"
#define BFD_OVSDB_IF_SESSION_STATE_STR_UP		"up"

  int remote_diag;
  int local_diag;
#define BFD_OVSDB_IF_SESSION_DIAG_NONE				0 // must match bfd::Diag::Value
#define BFD_OVSDB_IF_SESSION_DIAG_CONTROL_DETECT_EXPIRED	1 // must match bfd::Diag::Value
#define BFD_OVSDB_IF_SESSION_DIAG_ECHO_FAILED			2 // must match bfd::Diag::Value
#define BFD_OVSDB_IF_SESSION_DIAG_NEIGHBOR_SESSION_DOWN		3 // must match bfd::Diag::Value
#define BFD_OVSDB_IF_SESSION_DIAG_FORWARDING_RESET		4 // must match bfd::Diag::Value
#define BFD_OVSDB_IF_SESSION_DIAG_PATH_DOWN			5 // must match bfd::Diag::Value
#define BFD_OVSDB_IF_SESSION_DIAG_CONCAT_PATH_DOWN		6 // must match bfd::Diag::Value
#define BFD_OVSDB_IF_SESSION_DIAG_ADMIN_DOWN			7 // must match bfd::Diag::Value
#define BFD_OVSDB_IF_SESSION_DIAG_REVERSE_CONCAT_PATH_DOWN	8 // must match bfd::Diag::Value
#define BFD_OVSDB_IF_SESSION_DIAG_MAX				31 // must match bfd::Diag::Value

#define BFD_OVSDB_IF_SESSION_DIAG_STR_NONE			"none"
#define BFD_OVSDB_IF_SESSION_DIAG_STR_CONTROL_DETECT_EXPIRED	"control_detect_expired"
#define BFD_OVSDB_IF_SESSION_DIAG_STR_ECHO_FAILED		"echo_failed"
#define BFD_OVSDB_IF_SESSION_DIAG_STR_NEIGHBOR_SESSION_DOWN	"neighbor_session_down"
#define BFD_OVSDB_IF_SESSION_DIAG_STR_FORWARDING_RESET		"forwarding_reset"
#define BFD_OVSDB_IF_SESSION_DIAG_STR_PATH_DOWN			"path_down"
#define BFD_OVSDB_IF_SESSION_DIAG_STR_CONCAT_PATH_DOWN		"concat_path_down"
#define BFD_OVSDB_IF_SESSION_DIAG_STR_ADMIN_DOWN		"admin_down"
#define BFD_OVSDB_IF_SESSION_DIAG_STR_REVERSE_CONCAT_PATH_DOWN	"reverse_concat_path_down"
#define BFD_OVSDB_IF_SESSION_DIAG_STR_MAX			"max_diagnostics"

#if 0
    uint8_t detectMulti;
    uint32_t desiredMinTx;
    uint32_t requiredMinRx;

    bool controlPlaneIndependent;
    bool adminUpPollWorkaround;

    uint32_t desiredMinTxInterval;
    uint32_t useDesiredMinTxInterval;
    uint32_t defaultDesiredMinTxInterval;
    uint32_t requiredMinRxInterval;
    uint32_t useRequiredMinRxInterval;
#endif

    uint8_t remoteMultiplier;
    uint32_t remoteMinTxInterval;
    uint32_t remoteMinRxInterval;

    uint32_t transmitInterval;  // scheduled transmit interval
    uint64_t detectionTime; // Current detection time for timeouts

#if 0
    bool isHoldingState;
    bool isSuspended;
#endif

  uint8_t action;
#define BFD_OVSDB_IF_SESSION_ACTION_ADD		1
#define BFD_OVSDB_IF_SESSION_ACTION_MODIFY	2
#define BFD_OVSDB_IF_SESSION_ACTION_DEL		3

  uint32_t  valid;
#define BFD_OVSDB_IF_SESSION_VALID_SESSION_ID	0
#define BFD_OVSDB_IF_SESSION_VALID_LOCAL_STATE	1
#define BFD_OVSDB_IF_SESSION_VALID_REMOTE_STATE	2
#define BFD_OVSDB_IF_SESSION_VALID_LOCAL_DIAG	3
#define BFD_OVSDB_IF_SESSION_VALID_REMOTE_DIAG	4
#define BFD_OVSDB_IF_SESSION_VALID_REMOTE_MULTI	5
#define BFD_OVSDB_IF_SESSION_VALID_REMOTE_MIN_TX	6
#define BFD_OVSDB_IF_SESSION_VALID_REMOTE_MIN_RX	7
#define BFD_OVSDB_IF_SESSION_VALID_TRANSMIT_INTERVAL	8
#define BFD_OVSDB_IF_SESSION_VALID_DETECTION_TIME	9

} bfdOvsdbIfSession_t;


bool bfdBackendHandleSession(void *ovsCmdP, bfdOvsdbIfSession_t *bfd_if_session);

bool bfdOvsdbIfUpdateSession(bfdOvsdbIfSession_t *bfd_if_session);

#ifdef __cplusplus
}
#endif

#endif /* BFD_OVSDB_IF_H */
