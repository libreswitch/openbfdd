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
 **************************************************************************/

#include "common.h"
#include "CommandProcessor.h"
#include "utils.h"
#include "bfd.h"
#include "SmartPointer.h"
#include "Beacon.h"
#include "Scheduler.h"
#include "Session.h"
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <stdarg.h>
#include <iostream>
#include <unistd.h>
#include "TimeSpec.h"

#include "SockAddr.h"
#include "bfdOvsdbBackend.h"
#include "bfdOvsdbIf.h"

using namespace std;


class OvsCommandProcessor : public CommandProcessor
{

protected:
  Beacon *m_beacon; // never null, never changes

  //
  // These are protected by m_mainLock
  //
  QuickLock m_mainLock;
  pthread_t m_listenThread;
  volatile bool m_isThreadRunning;
  volatile bool m_threadInitComplete; // Set to true after  m_isThreadRunning set true the first time
  volatile bool m_threadStartupSuccess;   //only valid after m_isThreadRunning has been set to true.
  volatile bool m_stopListeningRequested;
  WaitCondition m_threadStartCondition;

public:
  OvsCommandProcessor(Beacon *beacon) : CommandProcessor(*beacon),
     m_beacon(beacon),
     m_mainLock(true),
     m_isThreadRunning(false),
     m_threadInitComplete(false),
     m_threadStartupSuccess(true),
     m_stopListeningRequested(false)
  {
  }

  virtual ~OvsCommandProcessor()
  {
    StopListening();
    bfd_ovsdb_exit();
  }

  /**
   * See CommandProcessor::BeginListening().
   */
  virtual bool BeginListening(const SockAddr &ATTR_UNUSED(addr));

  /**
   * See CommandProcessor::StopListening().
   */
  virtual void StopListening();

  typedef intptr_t(OvsCommandProcessor::*BeaconCallback)(Beacon *beacon, void *userdata);

  struct BeaconCallbackData
  {
	  OvsCommandProcessor *me;
	  void *userdata;
	  BeaconCallback callback;
	  bool wasShuttingDown;
	  intptr_t result;
	  bool exceptionThrown;
  };

  static void handleBeaconCallback(Beacon *beacon, void *userdata)
  {
	  BeaconCallbackData *data = (BeaconCallbackData *)userdata;

	  if (beacon->IsShutdownRequested())
	  {
		  data->wasShuttingDown = true;
		  return;
	  }

	  try
	  {
		  data->result = (data->me->*(data->callback))(beacon, data->userdata);
	  }
	  catch (std::exception &e)  // catch all exceptions .. is this too broad?
	  {
		  data->exceptionThrown = true;
		  gLog.Message(Log::Error, "Beacon callback failed due to exception: %s", e.what());
	  }
  }

  bool doBeaconOperation(BeaconCallback callback, void *userdata, intptr_t *result);
  intptr_t ovsSetGlobals(Beacon *beacon, void *userdata);
  intptr_t ovsCreateSession(Beacon *beacon, void *userdata);
  intptr_t ovsModifySession(Beacon *beacon, void *userdata);
  intptr_t ovsDeleteSession(Beacon *beacon, void *userdata);

protected:

  static void* doListenThreadCallback(void *arg)
  {
    reinterpret_cast<OvsCommandProcessor *>(arg)->doListenThread();
    return NULL;
  }

  void doListenThread();

  /**
   *
   * Call only from listen thread.
   * Call with  m_mainLock held.
   *
   * @return bool - false if listening setup failed.
   */
  bool initListening()
  {
    // Do this so low memory will not cause distorted messages
    if (!UtilsInitThread())
    {
      gLog.Message(Log::Error,  "Failed to initialize OVS listen thread. TLS memory failure.");
      return false;
    }

    gLog.Optional(Log::App, "Listening for OVS commands");

    return true;
  }

  /**
   * Checks if a shutdown has been requested. Do not call while holding
   * m_mainLock.
   *
   *
   *
   * @return bool - True if a shutdown was requested.
   */
  bool isStopListeningRequested()
  {
    AutoQuickLock lock(m_mainLock, true);
    return m_stopListeningRequested;
  }

private:


}; // class OvsCommandProcessor

bool
OvsCommandProcessor::BeginListening(const SockAddr &ATTR_UNUSED(addr))
{
	AutoQuickLock lock(m_mainLock, true);

	pthread_attr_t attr;

	if (m_isThreadRunning)
	{
		LogVerifyFalse("OVS Command Processer already running.");
		return true;
	}

	if (pthread_attr_init(&attr))
		return false;
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);  // we will handle synchronizing

	//m_address = addr;
	m_isThreadRunning = false;
	m_threadInitComplete = false;
	m_threadStartupSuccess = true;
	m_stopListeningRequested = false;

	if (pthread_create(&m_listenThread, &attr, doListenThreadCallback, this))
		return false;

	// Wait for listening, or error.
	while (true)
	{
		lock.LockWait(m_threadStartCondition);

		if (!m_threadInitComplete)
			continue; // spurious signal.

		// We can now allow the worker thread to shutdown if it wants to.
		if (!m_threadStartupSuccess)
		{
			lock.UnLock();
			StopListening();  // Ensure that thread is finished before we return...in case we try again immediately.
			return false;
		}

		break;
	}

	return true;
}

void
OvsCommandProcessor::StopListening()
{
	AutoQuickLock lock(m_mainLock, true);

	if (!m_isThreadRunning)
		return;

	m_stopListeningRequested = true;

	// We need to wait for it to
	while (m_isThreadRunning)
		lock.LockWait(m_threadStartCondition);
}

void
OvsCommandProcessor::doListenThread()
{
	bool initSuccess;
	AutoQuickLock lock(m_mainLock, true);

	gLog.Optional(Log::AppDetail, "OVS Listen Thread Started");

	initSuccess = initListening();
	m_threadStartupSuccess = initSuccess;
	m_isThreadRunning = true;
	m_threadInitComplete = true;

	// Signal setup completed (success, or failure).
	lock.SignalAndUnlock(m_threadStartCondition);

	// do Stuff
	if (initSuccess)
	{
		while (1) {
			if (isStopListeningRequested())
				break;

			//gLog.Message(Log::Debug, "BFD: Calling bfd_ovsdb_init_poll_loop:\n");
			/* hook with OVS IF calls */
			bfd_ovsdb_init_poll_loop();
			//gLog.Message(Log::Debug, "BFD: Returned from bfd_ovsdb_init_poll_loop:\n");
		}
	}

	lock.Lock();
	m_isThreadRunning = false;
	lock.SignalAndUnlock(m_threadStartCondition);
	gLog.Optional(Log::AppDetail, "OVS Listen Thread Shutdown");

	return;
}


/**
 * Queues a beacon callback. Does not return until operation is completed.
 *
 * @param userdata
 *
 * @return bool - false on failure to run the callback.
 */
bool
OvsCommandProcessor::doBeaconOperation(BeaconCallback callback, void *userdata, intptr_t *result = NULL)
{
	BeaconCallbackData data;
	data.me = this;
	data.userdata = userdata;
	data.callback = callback;
	data.wasShuttingDown = false;
	data.result = 0;
	data.exceptionThrown = false;

	if (!m_beacon->QueueOperation(handleBeaconCallback, &data, true /* waitForCompletion*/))
	{
		gLog.Message(Log::Error, "Unable to Queue DB request (beacon is shutting down or low memory)");
		return false;
	}

	if (data.exceptionThrown)
	{
		gLog.Message(Log::Error, "Unable to Queue DB request because an exception was thrown. Likely out of memory");
		return false;
	}

	if (data.wasShuttingDown)
	{
		gLog.Message(Log::Error, "Unable to Queue DB request because beacon is shutting down");
		return false;
	}

	if (result)
		*result = data.result;

	return true;
}

intptr_t
OvsCommandProcessor::ovsSetGlobals(Beacon *beacon, void *userdata)
{
	bfdOvsdbIfGlobal_t *bfd_if_global = reinterpret_cast<bfdOvsdbIfGlobal_t *>(userdata);

	if (IS_VALID(bfd_if_global->valid, BFD_OVSDB_IF_GLOBAL_MIN_RX_INTERVAL)) {
		gLog.Message(Log::Debug,  "Setting Min_Rx to %d",  bfd_if_global->minRxInterval);
		beacon->SetDefMinTxInterval(bfd_if_global->minRxInterval);
	}

	if (IS_VALID(bfd_if_global->valid, BFD_OVSDB_IF_GLOBAL_MIN_TX_INTERVAL)) {
		gLog.Message(Log::Debug,  "Setting Min_Tx to %d",  bfd_if_global->minTxInterval);
		beacon->SetDefMinTxInterval(bfd_if_global->minTxInterval);
	}

	if (IS_VALID(bfd_if_global->valid, BFD_OVSDB_IF_GLOBAL_MULTIPLIER)) {
		gLog.Message(Log::Debug,  "Setting Multiplier to %d",  bfd_if_global->multiplier);
		beacon->SetDefMulti(uint8_t(bfd_if_global->multiplier));
	}

	return true;
}

intptr_t
OvsCommandProcessor::ovsCreateSession(Beacon *beacon, void *userdata)
{
	SessionID *addr = reinterpret_cast<SessionID *>(userdata);

	if (!LogVerify(addr->HasIpAddresses()))
		return 0;

	return beacon->StartActiveSession(addr->whichRemoteAddr, addr->whichLocalAddr);
}

intptr_t
OvsCommandProcessor::ovsModifySession(Beacon *beacon, void *userdata)
{
	SessionID *addr = reinterpret_cast<SessionID *>(userdata);

	if (!LogVerify(addr->HasIpAddresses()))
		return 0;

	return beacon->StartActiveSession(addr->whichRemoteAddr, addr->whichLocalAddr);
}

intptr_t
OvsCommandProcessor::ovsDeleteSession(Beacon *beacon, void *userdata)
{
	SessionID *addr = reinterpret_cast<SessionID *>(userdata);
	Session *session = NULL;

	if (!LogVerify(addr->HasIpAddresses()))
		return 0;

	session = beacon->FindSessionIp(addr->whichRemoteAddr, addr->whichLocalAddr);
	if ( !session ) {
		return false;
	}

	beacon->KillSession(session);
	return true;
}

CommandProcessor* MakeOvsCommandProcessor(Beacon *beacon)
{
	OvsCommandProcessor *ovsCmdProc = new OvsCommandProcessor(beacon);

	/* Initialize Beacon context for OVS interface functions */
	bfd_ovsdb_init_context((void *)ovsCmdProc);

	return ovsCmdProc;
}

bool
bfdBackendSetGlobals(void *ovsCmdP, bfdOvsdbIfGlobal_t *bfd_if_global)
{
	OvsCommandProcessor *ovsCmdProc = reinterpret_cast<OvsCommandProcessor *>(ovsCmdP);
	intptr_t result;

	if (ovsCmdProc->doBeaconOperation(&OvsCommandProcessor::ovsSetGlobals, bfd_if_global, &result)) {
		if (result)
			gLog.Message(Log::Debug,  "Set global timers successfully, min_rx=%d, min_tx=%d, multi=%d",
					bfd_if_global->minRxInterval, bfd_if_global->minTxInterval, bfd_if_global->multiplier);
		else
			gLog.Message(Log::Debug,  "Failed set global timers");
	}

	return true;
}

bool
bfdBackendHandleSession(void *ovsCmdP, bfdOvsdbIfSession_t *bfd_if_session)
{
	OvsCommandProcessor *ovsCmdProc = reinterpret_cast<OvsCommandProcessor *>(ovsCmdP);
	IpAddr remote;
	IpAddr local;
	SessionID session_id;
	intptr_t result;

	if (!remote.FromString(bfd_if_session->remote_address)) {
		return false;
	}
	if (!local.FromString(bfd_if_session->local_address)) {
		return false;
	}

	if (bfd_if_session->action == BFD_OVSDB_IF_SESSION_ACTION_ADD) {
		session_id.Clear();
		session_id.SetAddress(true, local);
		session_id.SetAddress(false, remote);
		if (ovsCmdProc->doBeaconOperation(&OvsCommandProcessor::ovsCreateSession, &session_id, &result)) {
			if (result) {
				gLog.Message(Log::Debug,  "New session created for remote=%s local=%s", remote.ToString(), local.ToString());
				return true;
			} else {
				gLog.Message(Log::Debug,  "Failed to create New for remote=%s local=%s", remote.ToString(), local.ToString());
			}
		}
	} else if (bfd_if_session->action == BFD_OVSDB_IF_SESSION_ACTION_MODIFY) {
		session_id.Clear();
		session_id.SetAddress(true, local);
		session_id.SetAddress(false, remote);
		if (ovsCmdProc->doBeaconOperation(&OvsCommandProcessor::ovsModifySession, &session_id, &result)) {
			if (result) {
				gLog.Message(Log::Debug,  "Session modified for remote=%s local=%s", remote.ToString(), local.ToString());
				return true;
			} else {
				gLog.Message(Log::Debug,  "Failed to modify session for remote=%s local=%s", remote.ToString(), local.ToString());
			}
		}
	} else if (bfd_if_session->action == BFD_OVSDB_IF_SESSION_ACTION_DEL) {
		session_id.Clear();
		session_id.SetAddress(true, local);
		session_id.SetAddress(false, remote);
		if (ovsCmdProc->doBeaconOperation(&OvsCommandProcessor::ovsDeleteSession, &session_id, &result)) {
			if (result) {
				gLog.Message(Log::Debug,  "Session deleted for remote=%s local=%s", remote.ToString(), local.ToString());
				return true;
			} else {
				gLog.Message(Log::Debug,  "Failed to delete session for remote=%s local=%s", remote.ToString(), local.ToString());
			}
		}
	}

	return false;
}


bool
bfdBackendUpdateSessionDefaults(char *remote, char *local)
{
	bfdOvsdbIfSession_t bfd_if_session;

	memset(&bfd_if_session, 0, sizeof(bfdOvsdbIfSession_t));
	bfd_if_session.remote_address = remote;
	bfd_if_session.local_address = local;

	bfd_if_session.local_state = BFD_OVSDB_IF_SESSION_STATE_DOWN;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_LOCAL_STATE);

	bfd_if_session.remote_state = BFD_OVSDB_IF_SESSION_STATE_DOWN;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_STATE);

	if (!bfdOvsdbIfUpdateSession(&bfd_if_session)) {
		gLog.Message(Log::Error,  "Failed to Update Session default state to OVS.");
		return false;
	}

	return true;
}

bool
bfdBackendUpdateSessionChange(Session *session)
{
	bfdOvsdbIfSession_t bfd_if_session;
	Session::ExtendedStateInfo exInfo;

	memset(&bfd_if_session, 0, sizeof(bfdOvsdbIfSession_t));
	bfd_if_session.sessionId = session->GetId();
	bfd_if_session.remote_address = const_cast<char *>(session->GetRemoteAddress().ToString());
	bfd_if_session.local_address = const_cast<char *>(session->GetLocalAddress().ToString());

	bfd_if_session.local_state = session->GetState();
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_LOCAL_STATE);
	bfd_if_session.remote_state = session->GetRemoteState();
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_STATE);

	session->GetExtendedState(exInfo);
	bfd_if_session.remote_diag = exInfo.remoteDiag;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_DIAG);
	bfd_if_session.local_diag = exInfo.localDiag;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_LOCAL_DIAG);

	bfd_if_session.remoteMultiplier = exInfo.remoteDetectMult;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_MULTI);

	bfd_if_session.remoteMinTxInterval = exInfo.remoteDesiredMinTxInterval;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_MIN_TX);

	bfd_if_session.remoteMinRxInterval = exInfo.remoteMinRxInterval;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_MIN_RX);

	bfd_if_session.transmitInterval = exInfo.transmitInterval;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_TRANSMIT_INTERVAL);
	bfd_if_session.detectionTime = exInfo.detectionTime;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_DETECTION_TIME);

	if (!bfdOvsdbIfUpdateSession(&bfd_if_session)) {
		gLog.Message(Log::Error,  "Failed to Update Session Change to OVS.");
		return false;
	}

	gLog.Message(Log::Debug, "DB variable state before update: State=%d, Remote_state=%d Diag=%d Remote_diag=%d\n",
			session->GetDbState(), session->GetDbRemoteState(),
			session->GetDbLocalDiag(), session->GetDbRemoteDiag());

	session->SetDbState(session->GetState());
	session->SetDbRemoteState(session->GetRemoteState());
	session->SetDbLocalDiag(exInfo.localDiag);
	session->SetDbRemoteDiag(exInfo.remoteDiag);

	gLog.Message(Log::Debug, "DB variable state after update: State=%d, Remote_state=%d Diag=%d Remote_diag=%d\n",
			session->GetDbState(), session->GetDbRemoteState(),
			session->GetDbLocalDiag(), session->GetDbRemoteDiag());

	return true;
}
