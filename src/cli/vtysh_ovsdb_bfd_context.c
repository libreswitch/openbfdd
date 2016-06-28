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
 * Purpose: BFD CLI 'show running' implementation with OPS vtysh.
 **************************************************************************/

#include "vtysh/vty.h"
#include "vtysh/vector.h"
#include "vswitch-idl.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/utils/system_vtysh_utils.h"
#include "vtysh_ovsdb_bfd_context.h"

#include "bfdCommon.h"

vtysh_ret_val
vtysh_config_context_bfd_clientcallback(void *p_private)
{
    vtysh_ovsdb_cbmsg_ptr p_msg = (vtysh_ovsdb_cbmsg *)p_private;
    const struct ovsrec_system *system_row;
    int interval, min_rx, decay_min_rx;

    system_row = ovsrec_system_first(p_msg->idl);
    if(system_row) {
        if (system_row->n_bfd_enable > 0) {
            vtysh_ovsdb_cli_print(p_msg, "bfd enable");
        }

        interval = smap_get_int(&system_row->bfd_global_params,
                BFD_SMAP_KEY_MIN_TX, BFD_GLOBAL_DEFAULT_MIN_TX),
             min_rx = smap_get_int(&system_row->bfd_global_params,
                     BFD_SMAP_KEY_MIN_RX, BFD_GLOBAL_DEFAULT_MIN_RX),
             decay_min_rx = smap_get_int(&system_row->bfd_global_params,
                     BFD_SMAP_KEY_DECAY_MIN_RX, BFD_GLOBAL_DEFAULT_DECAY_MIN_RX);

        if ((interval != BFD_GLOBAL_DEFAULT_MIN_TX) ||
                (min_rx != BFD_GLOBAL_DEFAULT_MIN_RX) ||
                (decay_min_rx != BFD_GLOBAL_DEFAULT_DECAY_MIN_RX)) {
            vtysh_ovsdb_cli_print(p_msg, "bfd interval %d min_rx %d multiplier %d",
                    interval, min_rx, decay_min_rx);
        }
    }

    return e_vtysh_ok;
}
