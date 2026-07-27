// SPDX-License-Identifier: GPL-2.0-only
//
//! namesrv server wire (block 0x200..=0x2FF). Cap broker for
//! userland-published service endpoints. Publishers REGISTER,
//! consumers LOOKUP. unit_mgr (init) subscribes to register events.

pub const NAMESRV_REGISTER: u64 = 0x200;
pub const NAMESRV_UNREGISTER: u64 = 0x201;
pub const NAMESRV_LOOKUP: u64 = 0x210;
pub const NAMESRV_LOOKUP_NONBLOCK: u64 = 0x211;
pub const NAMESRV_LOOKUP_TIMEOUT: u64 = 0x212;
pub const NAMESRV_SUBSCRIBE: u64 = 0x220;
pub const NAMESRV_UNSUBSCRIBE: u64 = 0x221;
pub const NAMESRV_LIST: u64 = 0x230;
pub const NAMESRV_LIST_BY_PREFIX: u64 = 0x231;
pub const NAMESRV_GRANT_PUBLISHER: u64 = 0x282;
pub const NAMESRV_OWNER_EXITED: u64 = 0x283;
pub const NAMESRV_SUBSCRIBE_REGISTER: u64 = 0x285;
pub const NAMESRV_REGISTER_EVENT: u64 = 0x286;
