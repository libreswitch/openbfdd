/**************************************************************************
 * Copyright (c) 2010-2013, LinkedIn Corp.
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
 * Purpose: This file contains function declarations that are common
            between BFD Backend code & CLI
 **************************************************************************/

#ifndef _BFD_COMMON_H
#define _BFD_COMMON_H


#define BFD_GLOBAL_MIN_RX_MIN           15      /* In milliseconds */
#define BFD_GLOBAL_MIN_RX_MAX           300000  /* In milliseconds */
#define BFD_GLOBAL_MIN_TX_MIN           15      /* In milliseconds */
#define BFD_GLOBAL_MIN_TX_MAX           300000  /* In milliseconds */
#define BFD_GLOBAL_DECAY_MIN            0       /* value of 0 will disable */
#define BFD_GLOBAL_DECAY_MAX            255     /* In milliseconds */

#define BFD_GLOBAL_DEFAULT_MIN_RX       1000
#define BFD_GLOBAL_DEFAULT_MIN_TX       1000
#define BFD_GLOBAL_DEFAULT_DECAY_MIN_RX 3

#define BFD_SMAP_KEY_ENABLED            "bfd_enable"
#define BFD_SMAP_KEY_MIN_TX             "min_tx"
#define BFD_SMAP_KEY_MIN_RX             "min_rx"
#define BFD_SMAP_KEY_DECAY_MIN_RX       "decay_min_rx"

#endif /* _BFD_COMMON_H */
