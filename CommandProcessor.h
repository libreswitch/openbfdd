/**************************************************************
* Copyright (c) 2010-2013, Dynamic Network Services, Inc.
* Jake Montgomery (jmontgomery@dyn.com) & Tom Daly (tom@dyn.com)
* Distributed under the FreeBSD License - see LICENSE
***************************************************************/
// Class for handling command communication with the control app.
#pragma once

#include "SockAddr.h"

class Beacon;

/**
 * Interface factory. Use delete to free this.
 *
 * Requires UtilsInit() to have been called.
 *
 * @throw - May throw an exception.
 *
 * @return CommandProcessor* - Will not return NULL.
 */
class CommandProcessor* MakeCommandProcessor(Beacon &beacon);

/**
 * This interface handles all communication between this beacon and the control
 * utility. Most of the processing is done in a worker thread.
 *
 */
class CommandProcessor
{
public:
  virtual ~CommandProcessor() { };

  /**
   *
   * Starts listening, and handling commands, on the given address and port. This
   * will block until socket communication can be established. This should not be
   * called from different threads simultaneously.
   *
   * @param addr [in] - The address and port on which to listen.
   *
   * @return bool - false if communication could not be set up.
   */
  virtual bool BeginListening(const SockAddr &addr) = 0;

  /**
   * Halts listening and waits for the listen thread to terminate.
   * Do not call simultaneously with BeginListening().
   */
  virtual void StopListening() = 0;

protected:
  CommandProcessor(Beacon &) { };
};

#ifdef ENABLE_OVSDB
  /**
   * Holds enough info to locate a session, or marks for "All" sessions.
   *
   */
  struct SessionID
  {
    SessionID() : allSessions(false), whichId(0), whichRemoteAddr(), whichLocalAddr() { }
    void Clear() { allSessions = false; whichId = 0; whichRemoteAddr.clear(); whichLocalAddr.clear();}
    bool IsValid() const { return allSessions || whichId != 0 || HasIpAddresses();}
    bool HasIpAddresses() const { return  whichRemoteAddr.IsValid() && whichLocalAddr.IsValid();}
    void SetAddress(bool local, const IpAddr &addr) { if (local)
        whichLocalAddr = addr;
      else
        whichRemoteAddr = addr;}

    bool allSessions;
    uint32_t whichId;
    IpAddr whichRemoteAddr;
    IpAddr whichLocalAddr;
  };
#endif