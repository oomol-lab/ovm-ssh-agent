/*
 * SPDX-FileCopyrightText: 2024 OOMOL, Inc. <https://www.oomol.com>
 * SPDX-License-Identifier: MPL-2.0
 */

package types

type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}
