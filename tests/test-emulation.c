/*
 * Copyright (C) 2026 Canonical, Ltd.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "fpi-device.h"
#include "fpi-test-emulation.h"

gboolean
  (fpi_device_emulation_mode_enabled) (FpDevice *device)
{
  static gsize emulation_mode = 0;

  if (g_once_init_enter (&emulation_mode))
    g_once_init_leave (&emulation_mode,
                       g_strcmp0 (g_getenv (FPI_EMULATION_ENV_VAR), "1") == 0 ?
                       TRUE : G_MAXSIZE);

  return emulation_mode == TRUE;
}
